package openbaogroupalias

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

func TestCRDValidation_OpenBaoGroupAlias_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoGroupAlias {
		a := &v1alpha1.OpenBaoGroupAlias{}
		a.Namespace = ns
		a.Spec.MountAccessor = "auth_oidc_abc"
		a.Spec.CanonicalID = "g-100"
		return a
	}

	cases := []struct {
		name    string
		mutate  func(a *v1alpha1.OpenBaoGroupAlias)
		invalid bool
		hint    string
	}{
		{
			name:    "valid-baseline",
			mutate:  func(a *v1alpha1.OpenBaoGroupAlias) {},
			invalid: false,
			hint:    "canonical valid spec must admit",
		},
		{
			name:    "empty-mountAccessor-rejected",
			mutate:  func(a *v1alpha1.OpenBaoGroupAlias) { a.Spec.MountAccessor = "" },
			invalid: true,
			hint:    "MinLength=1 on spec.mountAccessor",
		},
		{
			name: "groupref-no-name-rejected",
			mutate: func(a *v1alpha1.OpenBaoGroupAlias) {
				a.Spec.CanonicalID = ""
				a.Spec.CanonicalGroupRef = &v1alpha1.OpenBaoGroupRef{}
			},
			invalid: true,
			hint:    "Required + MinLength on spec.canonicalGroupRef.name",
		},
		{
			name: "groupref-with-name-accepted",
			mutate: func(a *v1alpha1.OpenBaoGroupAlias) {
				a.Spec.CanonicalID = ""
				a.Spec.CanonicalGroupRef = &v1alpha1.OpenBaoGroupRef{Name: "team-a"}
			},
			invalid: false,
			hint:    "groupRef with name admits",
		},
		{
			name:    "openbaonamespace-uppercase-rejected",
			mutate:  func(a *v1alpha1.OpenBaoGroupAlias) { a.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "Pattern on spec.openbaoNamespace rejects uppercase",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := validBase()
			a.Name = "t-" + tc.name
			tc.mutate(a)
			err := cl.Create(ctx, a)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoGroupAlias{
					ObjectMeta: metav1.ObjectMeta{Name: a.Name, Namespace: ns},
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
