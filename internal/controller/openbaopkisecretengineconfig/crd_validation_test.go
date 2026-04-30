package openbaopkisecretengineconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
)

var (
	testEnv *envtest.Environment
	testCfg *rest.Config
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		os.Exit(m.Run())
	}
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "..", "config", "crd", "bases"),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest start failed: %v\n", err)
		os.Exit(1)
	}
	testCfg = cfg
	code := m.Run()
	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "envtest stop failed: %v\n", err)
	}
	os.Exit(code)
}

func newEnvtestClient(t *testing.T) client.Client {
	t.Helper()
	if testCfg == nil {
		t.Fatal("CRD validation requires envtest. KUBEBUILDER_ASSETS is unset; " +
			"run via `make test`, not bare `go test ./...`.")
	}
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	cl, err := client.New(testCfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	return cl
}

// TestCRDValidation_OpenBaoPKIConfig_RejectsInvalid drives every
// kubebuilder marker the controller relies on through admission:
// Required, Pattern, Enum, MinLength, MaxLength.
func TestCRDValidation_OpenBaoPKIConfig_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoPKISecretEngineConfig {
		c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
		c.Namespace = ns
		c.Spec.Path = "pki"
		c.Spec.PKIType = "root"
		c.Spec.CommonName = "Test CA"
		return c
	}

	cases := []struct {
		name    string
		mutate  func(c *v1alpha1.OpenBaoPKISecretEngineConfig)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {},
			invalid: false,
			hint:    "canonical valid spec must admit",
		},
		{
			name:    "empty-path-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.Path = "" },
			invalid: true,
			hint:    "MinLength=1 on spec.path",
		},
		{
			name:    "empty-commonName-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.CommonName = "" },
			invalid: true,
			hint:    "MinLength=1 on spec.commonName",
		},
		{
			name:    "pkiType-non-enum-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.PKIType = "intermediate" },
			invalid: true,
			hint:    "Enum=root on spec.pkiType (intermediate not implemented)",
		},
		{
			name:    "keyType-non-enum-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.KeyType = "dsa" },
			invalid: true,
			hint:    "Enum=rsa;ec;ed25519 on spec.keyType",
		},
		{
			name:    "ttl-pattern-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.TTL = "10 hours" },
			invalid: true,
			hint:    "Pattern on spec.ttl rejects whitespace/word forms",
		},
		{
			name:    "ttl-pattern-accepted",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.TTL = "8760h" },
			invalid: false,
			hint:    "Pattern on spec.ttl accepts bao duration shape",
		},
		{
			name:    "openbaoNamespace-uppercase-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "Pattern on spec.openbaoNamespace rejects uppercase",
		},
		{
			name:    "keyBits-too-large-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.KeyBits = 16384 },
			invalid: true,
			hint:    "Maximum=8192 on spec.keyBits",
		},
		{
			name:    "path-pattern-rejected-leading-slash",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.Path = "/pki" },
			invalid: true,
			hint:    "Pattern on spec.path rejects leading slash",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validBase()
			c.Name = "t-" + tc.name
			tc.mutate(c)
			err := cl.Create(ctx, c)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
					ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: ns},
				})
			})
			if tc.invalid {
				require.Error(t, err, tc.hint)
			} else {
				require.NoError(t, err, tc.hint)
			}
		})
	}
}
