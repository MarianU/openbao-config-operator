package openbaoauthmethod

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

func TestCRDValidation_OpenBaoAuthMethod_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()
	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoAuthMethod {
		m := &v1alpha1.OpenBaoAuthMethod{}
		m.Namespace = ns
		m.Spec.Path = "oidc"
		m.Spec.Type = "oidc"
		return m
	}

	cases := []struct {
		name    string
		mutate  func(m *v1alpha1.OpenBaoAuthMethod)
		invalid bool
		hint    string
	}{
		{"valid-baseline", func(m *v1alpha1.OpenBaoAuthMethod) {}, false, "canonical valid spec"},
		{"empty-path", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Path = "" }, true, "Required + MinLength=1 on spec.path"},
		{"type-non-enum", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Type = "transit" }, true, "Enum on spec.type rejects secret-engine kinds"},
		{"type-cert-accepted", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Type = "cert" }, false, "Enum allows cert"},
		{"type-jwt-accepted", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Type = "jwt" }, false, "Enum allows jwt"},
		{"type-kubernetes-accepted", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Type = "kubernetes" }, false, "Enum allows kubernetes"},
		{"defaultleasettl-pattern-rejected", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Config.DefaultLeaseTTL = "1 day" }, true, "Pattern on spec.config.defaultLeaseTtl"},
		{"defaultleasettl-pattern-accepted", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Config.DefaultLeaseTTL = "24h" }, false, "Pattern accepts bao duration"},
		{"listingvisibility-non-enum", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Config.ListingVisibility = "weird" }, true, "Enum on listingVisibility"},
		{"listingvisibility-unauth", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.Config.ListingVisibility = "unauth" }, false, "Enum allows unauth"},
		{"openbaonamespace-uppercase", func(m *v1alpha1.OpenBaoAuthMethod) { m.Spec.OpenBaoNamespace = "ACME/" }, true, "Pattern rejects uppercase"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			m := validBase()
			m.Name = "t-" + tc.name
			tc.mutate(m)
			err := cl.Create(ctx, m)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoAuthMethod{
					ObjectMeta: metav1.ObjectMeta{Name: m.Name, Namespace: ns},
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
