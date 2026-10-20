package openbaoidentitytokenrole

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

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
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

func TestCRDValidation_OpenBaoIdentityTokenRole_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()
	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoIdentityTokenRole {
		r := &v1alpha1.OpenBaoIdentityTokenRole{}
		r.Namespace = ns
		r.Spec.Key = "platform"
		return r
	}

	cases := []struct {
		name    string
		mutate  func(r *v1alpha1.OpenBaoIdentityTokenRole)
		invalid bool
		hint    string
	}{
		{"valid-baseline", func(r *v1alpha1.OpenBaoIdentityTokenRole) {}, false, "canonical valid spec"},
		{"empty-key-rejected", func(r *v1alpha1.OpenBaoIdentityTokenRole) { r.Spec.Key = "" }, true, "Required + MinLength=1 on spec.key"},
		{"specname-uppercase-rejected", func(r *v1alpha1.OpenBaoIdentityTokenRole) { r.Spec.Name = "BAD" }, true, "Pattern on spec.name rejects uppercase"},
		{"ttl-pattern-rejected", func(r *v1alpha1.OpenBaoIdentityTokenRole) { r.Spec.TTL = "1 week" }, true, "Pattern on spec.ttl rejects whitespace/words"},
		{"ttl-pattern-accepted", func(r *v1alpha1.OpenBaoIdentityTokenRole) { r.Spec.TTL = "30m" }, false, "Pattern on spec.ttl accepts bao duration"},
		{"openbaonamespace-uppercase-rejected", func(r *v1alpha1.OpenBaoIdentityTokenRole) { r.Spec.OpenBaoNamespace = "ACME/" }, true, "Pattern rejects uppercase"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := validBase()
			r.Name = "t-" + tc.name
			tc.mutate(r)
			err := cl.Create(ctx, r)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoIdentityTokenRole{
					ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: ns},
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
