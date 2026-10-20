package utils

import (
	"os"
	"strings"

	. "github.com/onsi/gomega"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
)

// NewTypedBaoClient builds a typed baoclient.Client from VAULT_ADDR /
// VAULT_TOKEN. The e2e suite uses this whenever it needs the typed
// per-CRD read/write helpers from internal/client (transit keys, PKI
// roles, identity groups, …); the BaoClient struct in bao.go covers
// the few endpoints the suite still hits over raw HTTP.
func NewTypedBaoClient() baoclient.Client {
	addr := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	tok := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	Expect(addr).NotTo(BeEmpty(), "VAULT_ADDR must be set for e2e")
	Expect(tok).NotTo(BeEmpty(), "VAULT_TOKEN must be set for e2e")

	addr = strings.TrimRight(addr, "/")
	if i := strings.Index(addr, "/ui/"); i >= 0 {
		addr = addr[:i]
	}

	c, err := baoclient.NewHTTPClient(addr, tok)
	Expect(err).NotTo(HaveOccurred())
	return c
}
