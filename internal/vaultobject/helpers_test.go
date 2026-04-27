package vaultobject

import "testing"

func TestCleansePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"slash-only", "/", ""},
		{"plain", "foo", "foo"},
		{"leading-slash", "/foo", "foo"},
		{"trailing-slash", "foo/", "foo"},
		{"both-slashes", "/foo/", "foo"},
		{"double-middle", "foo//bar", "foo/bar"},
		{"doubles-everywhere", "//foo//bar//", "foo/bar"},
		{"nested-path", "sys/policies/acl/my-policy", "sys/policies/acl/my-policy"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CleansePath(tc.in); got != tc.want {
				t.Errorf("CleansePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
