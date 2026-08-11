package openbaojwtoidcauthengineconfig

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

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
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

func TestCRDValidation_OpenBaoJWTOIDCAuthEngineConfig(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()
	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig {
		c := &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{}
		c.Namespace = ns
		c.Spec.Path = "oidc"
		c.Spec.OIDCDiscoveryURL = "https://accounts.example.com"
		return c
	}
	cases := []struct {
		name    string
		mutate  func(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig)
		invalid bool
	}{
		{"valid-baseline", func(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) {}, false},
		{"empty-path", func(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) { c.Spec.Path = "" }, true},
		{"oidc-response-mode-non-enum", func(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) {
			c.Spec.OIDCResponseMode = "weird"
		}, true},
		{"oidc-response-mode-form-post", func(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) {
			c.Spec.OIDCResponseMode = "form_post"
		}, false},
		{"openbaonamespace-uppercase", func(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) {
			c.Spec.OpenBaoNamespace = "ACME/"
		}, true},
		{"client-secret-ref-empty-name", func(c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) {
			c.Spec.OIDCClientSecretRef = &v1alpha1.OIDCClientSecretRef{}
		}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := validBase()
			c.Name = "t-" + tc.name
			tc.mutate(c)
			err := cl.Create(ctx, c)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{
					ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: ns},
				})
			})
			if tc.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
