package client

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

// The operator's CI-generated chart bakes placeholder VAULT_* env into its
// manifest. newSDKCfg must neutralize them when a per-connection TLS config
// is supplied, or vault.NewClient tries to load "some_client_cert" and the
// whole connection build fails. Guard against a regression by driving the
// resolver's constructors with the placeholders set and asserting they build.
func TestNewHTTPClientTLS_IgnoresPlaceholderVaultEnv(t *testing.T) {
	t.Setenv("VAULT_CACERT", "some_ca_cert")
	t.Setenv("VAULT_CLIENT_CERT", "some_client_cert")
	t.Setenv("VAULT_CLIENT_KEY", "some_client_key")
	t.Setenv("VAULT_TLS_SERVER_NAME", "some_tls_server_name")

	// A nil *tls.Config means env-based TLS; the pre-existing behavior keeps
	// only VAULT_CACERT clearing when the file is missing. So assert the
	// env-driven path is NOT what we exercise here for the placeholder bug.
	// The per-connection path (NewHTTPClientTLS with a non-nil tc) must build.
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	_, err := NewHTTPClientTLS("https://bao.example:8200", "s.test", tc)
	require.NoError(t, err, "placeholder VAULT_* must not break a per-connection client build")

	_, err = NewKubernetesAuthClientTLS("https://bao.example:8200", "k8s-operator", "op", "/var/run/secrets/openbao/token", tc)
	require.NoError(t, err, "placeholder VAULT_* must not break a kubernetes-auth client build")
}
