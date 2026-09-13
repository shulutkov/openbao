// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ory/dockertest/v4"
)

func setupTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b, storage := getTestBackend(t)

	data := map[string]any{
		"keytab":          testValidKeytab,
		"service_account": "testuser",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	return b, storage
}

func TestLogin(t *testing.T) {
	b, storage := setupTestBackend(t)

	connURL := prepareLDAPTestContainer(t)
	ldapReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      ldapConfPath,
		Storage:   storage,
		Data: map[string]any{
			"url": connURL,
		},
	}

	resp, err := b.HandleRequest(t.Context(), ldapReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	data := map[string]any{
		"authorization": "",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: connURL,
		},
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err == nil || resp == nil || resp.IsError() {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	if e, ok := err.(logical.HTTPCodedError); !ok || e.Code() != 401 {
		t.Fatalf("no 401 thrown. err: %s resp: %#v\n", err, resp)
	}

	if headerVal, ok := resp.Headers["www-authenticate"]; ok {
		if strings.Compare(headerVal[0], "Negotiate") != 0 {
			t.Fatalf("www-authenticate not set to Negotiate. err: %s resp: %#v\n", err, resp)
		}
	} else {
		t.Fatalf("no www-authenticate header. err: %s resp: %#v\n", err, resp)
	}
}

func prepareLDAPTestContainer(t *testing.T) string {
	pool := dockertest.NewPoolT(t, "")
	resource := pool.RunT(
		t, "quay.io/minio/openldap",
		dockertest.WithTag("latest"),
		dockertest.WithEnv([]string{
			"LDAP_TLS=false",
			"LDAP_DOMAIN=min.io", // Required for minio/openldap to boot up...
		}),
	)

	retURL := fmt.Sprintf("ldap://localhost:%s", resource.GetPort("389/tcp"))

	// exponential backoff-retry
	if err := pool.Retry(t.Context(), 10*time.Second, func() error {
		conn, err := ldap.DialURL(retURL)
		if err != nil {
			return err
		}
		defer conn.Close()

		if err := conn.Bind("cn=admin,dc=min,dc=io", "admin"); err != nil {
			return err
		}

		searchRequest := ldap.NewSearchRequest(
			"dc=min,dc=io",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(&(objectClass=*))",
			[]string{"dn", "cn"},
			nil,
		)
		if _, err := conn.Search(searchRequest); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("Could not connect to ldap auth docker container: %s", err)
	}

	return retURL
}

// TestAMountWithoutLDAPAuthenticatesByTicketAlone. A machine's name lives in the realm, which is the
// only place a machine has a name at all; the directory answers "which groups is this PERSON in".
// Demanding an address book entry for every host means inventing an account per machine so that a
// lookup can succeed, and then the account — not the ticket — is the thing that must be kept in
// step. So a mount with no config/ldap authenticates by ticket and issues a group-less token, and
// what such a caller may do is decided by the identity attached to its principal.
func TestAMountWithoutLDAPAuthenticatesByTicketAlone(t *testing.T) {
	// setupTestBackend configures the keytab and nothing else: no config/ldap, which is the machine
	// mount.
	b, storage := setupTestBackend(t)

	// The login must fail on the TICKET — there is none in this request — and not on the absence
	// of a directory.
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Storage:    storage,
		Data:       map[string]any{"authorization": "Negotiate not-a-real-token"},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	if err != nil && strings.Contains(err.Error(), "ldap backend not configured") {
		t.Fatalf("a mount with no directory refused before looking at the ticket: %v", err)
	}
	if err == nil && resp != nil && resp.Auth != nil {
		t.Fatal("a token was issued for a credential that is not one")
	}
}
