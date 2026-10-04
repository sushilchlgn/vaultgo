package main

import "testing"

func TestPatternMatches(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"db-password", "db-password", true},
		{"db-password", "db-password2", false},
		{"db-*", "db-password", true},
		{"db-*", "api-token", false},
		{"*", "anything", true},
		{"db-*", "db-", true},
	}
	for _, c := range cases {
		if got := patternMatches(c.pattern, c.name); got != c.want {
			t.Errorf("patternMatches(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestCallerAllowed(t *testing.T) {
	c := Caller{Scopes: []Scope{
		{Action: "read", Pattern: "db-*"},
		{Action: "write", Pattern: "db-password"},
	}}

	if !c.Allowed("read", "db-password") {
		t.Error("should be able to read db-password")
	}
	if !c.Allowed("write", "db-password") {
		t.Error("should be able to write db-password")
	}
	if c.Allowed("write", "db-other") {
		t.Error("write on db-other should be denied")
	}
	if c.Allowed("read", "api-token") {
		t.Error("read on api-token should be denied")
	}
}

func TestNoScopesMeansNoAccess(t *testing.T) {
	c := Caller{}
	if c.Allowed("read", "anything") || c.Allowed("write", "anything") {
		t.Error("a caller with no scopes must be denied everything")
	}
}

func TestParseScopes(t *testing.T) {
	scopes, err := parseScopes("read:db-*, write:db-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 {
		t.Fatalf("got %d scopes, want 2", len(scopes))
	}

	for _, bad := range []string{"", "read", "delete:x", "read:bad name!", "read:"} {
		if _, err := parseScopes(bad); err == nil {
			t.Errorf("parseScopes(%q) should fail", bad)
		}
	}
}