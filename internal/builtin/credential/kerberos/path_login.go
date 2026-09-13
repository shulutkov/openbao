// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/x/identity"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixKerberos,
		},
		Fields: map[string]*framework.FieldSchema{
			"authorization": {
				Type:        framework.TypeString,
				Description: `SPNEGO Authorization header. Required.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathLoginGet,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "login2",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginUpdate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "login",
				},
			},
		},
	}
}

func parseKeytab(b64EncodedKt string) (*keytab.Keytab, error) {
	decodedKt, err := base64.StdEncoding.DecodeString(b64EncodedKt)
	if err != nil {
		return nil, err
	}
	parsedKt := new(keytab.Keytab)
	if err := parsedKt.Unmarshal(decodedKt); err != nil {
		return nil, err
	}
	return parsedKt, nil
}

func (b *backend) pathLoginGet(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Headers: map[string][]string{
			"www-authenticate": {"Negotiate"},
		},
	}, logical.CodedError(401, "authentication required")
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	kerbCfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get kerberos config: %w", err)
	}
	if kerbCfg == nil {
		return nil, errors.New("backend kerberos not configured")
	}

	// A mount with no LDAP configuration authenticates by TICKET ALONE, and that is a deliberate
	// second shape rather than a half-configured first one.
	//
	// The directory answers "which groups is this person in", and a machine is not in it: its name
	// lives in the realm, which is the only place a machine has a name at all. Demanding an address
	// book entry for every host means inventing an account per machine so that a lookup can
	// succeed, and then the account — not the ticket — becomes the thing that must be kept in step.
	//
	// So: configure config/ldap on the mount people use, and leave it off the mount machines use.
	// A group-less token is the honest result there; what such a caller may do is decided by the
	// identity attached to its principal, not by a directory that has never heard of it.
	ldapCfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("unable to get ldap config: %w", err)
	}

	// Check for a CIDR match.
	if ldapCfg != nil && len(ldapCfg.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, ldapCfg.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	authorizationString := ""
	authorizationHeaders := req.Headers["Authorization"]
	if len(authorizationHeaders) > 0 {
		authorizationString = authorizationHeaders[0]
	} else {
		authorizationString = d.Get("authorization").(string)
	}

	kt, err := parseKeytab(kerbCfg.Keytab)
	if err != nil {
		return nil, fmt.Errorf("could not parse keytab: %w", err)
	}

	if kerbCfg.RemoveInstanceName {
		removeInstanceNameFromKeytab(kt)
	}

	s := strings.SplitN(authorizationString, " ", 2)
	if len(s) != 2 || s[0] != "Negotiate" {
		return b.pathLoginGet(ctx, req, d)
	}

	// The SPNEGOKRB5Authenticate method only calls an inner function if it's
	// successful. Let's use it to record success, and to retrieve the caller's
	// identity.
	username := ""
	authenticated := false
	// The Kerberos library this build carries puts the authenticated caller in the request context
	// under its own identity package's key — the same role goidentity played upstream, the same
	// two fields read below.
	var caller identity.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller = identity.FromHTTPRequestContext(r)
		if caller == nil {
			w.WriteHeader(400)
			_, _ = w.Write([]byte("identity credentials are not included"))
			return
		}
		b.Logger().Debug(fmt.Sprintf("identity: %+v", caller))
		username = caller.UserName()

		if kerbCfg.RemoveInstanceName {
			user := splitUsername(caller.UserName())
			if len(user) > 1 {
				username = user[0]
			}
		}

		// Verify that the realm on the LDAP config (if set) is the same as the identity's
		// realm. The UPNDomain denotes the realm on the LDAP config, and the identity
		// domain likewise identifies the realm. This is a case sensitive check.
		// This covers an edge case where, potentially, there has been drift between the LDAP
		// config's realm and the Kerberos realm. In such a case, it prevents a user from
		// passing Kerberos authentication, and then extracting group membership, and
		// therefore policies, from a separate directory.
		if ldapCfg != nil && ldapCfg.UPNDomain != "" && caller.Domain() != ldapCfg.UPNDomain {
			w.WriteHeader(400)
			_, _ = fmt.Fprintf(w, "identity domain of %q doesn't match LDAP upndomain of %q", caller.Domain(), ldapCfg.UPNDomain)
			return
		}
		authenticated = true
	})

	// Let's pass in a logger so we can get debugging information if anything
	// goes wrong.
	l := b.Logger().StandardLogger(&hclog.StandardLoggerOptions{
		InferLevels: true,
	})

	// Now let's use our inner handler to compose the overall function.
	authHTTPHandler := spnego.SPNEGOKRB5Authenticate(inner, kt, service.Logger(l), service.KeytabPrincipal(kerbCfg.ServiceAccount), service.DecodePAC(kerbCfg.DecodePAC))
	// Because the outer application strips off the raw request, we need to
	// re-compose it to use this authentication handler. Only the request
	// remote addr and headers are used anyways. We use an arbitrary port
	// of 8080 because it's not used for anything but logging, but is required
	// by an underlying parser.
	rebuiltReq := &http.Request{
		Header:     req.Headers,
		RemoteAddr: req.Connection.RemoteAddr + ":8080",
	}

	// Finally, execute the SPNEGO authentication check.
	w := &simpleResponseWriter{}
	authHTTPHandler.ServeHTTP(w, rebuiltReq)
	if !authenticated {
		resp := &logical.Response{
			Warnings: []string{string(w.body)},
		}
		return logical.RespondWithStatusCode(resp, req, w.statusCode)
	}

	// Now that they've passed the Kerb authentication, begin checking if
	// they're a member of an LDAP group that should have additional policies
	// attached.
	// The directory half, and only when this mount has one. A mount without config/ldap is the
	// machine mount: the ticket is the whole of the identity there.
	var allGroups []string
	if ldapCfg != nil {
		ldapClient := ldaputil.Client{
			Logger: b.Logger(),
			LDAP:   ldaputil.NewLDAP(),
		}

		ldapConnection, err := ldapClient.DialLDAP(ldapCfg.ConfigEntry)
		if err != nil {
			return nil, fmt.Errorf("could not connect to LDAP: %w", err)
		}
		if ldapConnection == nil {
			return nil, errors.New("invalid connection returned from LDAP dial")
		}

		// Clean ldap connection
		defer ldapConnection.Close()

		if len(ldapCfg.BindPassword) > 0 {
			err = ldapConnection.Bind(ldapCfg.BindDN, ldapCfg.BindPassword)
		} else {
			err = ldapConnection.UnauthenticatedBind(ldapCfg.BindDN)
		}
		if err != nil {
			return nil, fmt.Errorf("LDAP bind failed: %v", err)
		}

		userBindDN, err := ldapClient.GetUserBindDN(ldapCfg.ConfigEntry, ldapConnection, username)
		if err != nil {
			return nil, fmt.Errorf("unable to get user binddn: %w", err)
		}
		b.Logger().Debug("auth/ldap: User BindDN fetched", "username", caller.UserName(), "binddn", userBindDN)

		userDN, err := ldapClient.GetUserDN(ldapCfg.ConfigEntry, ldapConnection, userBindDN, username)
		if err != nil {
			return nil, fmt.Errorf("unable to get user dn: %w", err)
		}

		ldapGroups, err := ldapClient.GetLdapGroups(ldapCfg.ConfigEntry, ldapConnection, userDN, username)
		if err != nil {
			return nil, fmt.Errorf("unable to get ldap groups: %w", err)
		}
		b.Logger().Debug("auth/ldap: Groups fetched from server", "num_server_groups", len(ldapGroups), "server_groups", ldapGroups)
		allGroups = append(allGroups, ldapGroups...)
	}

	// Retrieve policies
	var policies []string
	for _, groupName := range allGroups {
		group, err := b.Group(ctx, req.Storage, groupName)
		if err != nil {
			b.Logger().Warn(fmt.Sprintf("unable to retrieve %s: %s", groupName, err.Error()))
			continue
		}
		if group == nil {
			b.Logger().Warn(fmt.Sprintf("unable to find %s, does not currently exist", groupName))
			continue
		}
		policies = append(policies, group.Policies...)
	}

	// Policies from each group may overlap
	policies = strutil.RemoveDuplicates(policies, true)
	auth := &logical.Auth{
		InternalData: map[string]any{},
		Metadata: map[string]string{
			"user":   caller.UserName(),
			"domain": caller.Domain(),
		},
		DisplayName: caller.UserName(),
		Alias:       &logical.Alias{Name: caller.UserName()},
	}

	if ldapCfg != nil {
		if err := ldapCfg.PopulateTokenAuth(auth, req); err != nil {
			return nil, fmt.Errorf("failed to populate auth information: %w", err)
		}
	}

	// This is done after PopulateTokenAuth because it forces Renewable to be true.
	// Renewable was always false at the time of the code's introduction, and we would
	// like to keep it the same until we have a concrete reason to change its behavior.
	auth.LeaseOptions = logical.LeaseOptions{
		Renewable: false,
	}

	// Combine our policies with the ones parsed from PopulateTokenAuth.
	if len(policies) > 0 {
		auth.Policies = append(auth.Policies, policies...)
	}

	// Add the LDAP groups so the Identity system can use them
	if kerbCfg.AddGroupAliases {
		for _, groupName := range allGroups {
			if groupName == "" {
				continue
			}
			auth.GroupAliases = append(auth.GroupAliases, &logical.Alias{
				Name: groupName,
			})
		}
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

type simpleResponseWriter struct {
	body       []byte
	statusCode int
}

func (w *simpleResponseWriter) Header() http.Header {
	return make(http.Header)
}

func (w *simpleResponseWriter) Write(b []byte) (int, error) {
	w.body = b
	return 0, nil
}

func (w *simpleResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}
