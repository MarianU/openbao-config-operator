package openbaojwtoidcauthenginerole

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

func TestCRDValidation_OpenBaoJWTOIDCAuthEngineRole(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()
	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoJWTOIDCAuthEngineRole {
		r := &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{}
		r.Namespace = ns
		r.Spec.Path = "oidc"
		r.Spec.RoleType = v1alpha1.JWTOIDCRoleTypeOIDC
		r.Spec.UserClaim = "email"
		return r
	}
	cases := []struct {
		name    string
		mutate  func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole)
		invalid bool
	}{
		{"valid-baseline", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) {}, false},
		{"empty-path", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.Path = "" }, true},
		{"empty-roletype", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.RoleType = "" }, true},
		{"non-enum-roletype", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.RoleType = "weird" }, true},
		{"jwt-roletype", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.RoleType = v1alpha1.JWTOIDCRoleTypeJWT }, false},
		{"empty-userclaim", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.UserClaim = "" }, true},
		{"specname-uppercase", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.Name = "BAD" }, true},
		{"tokenttl-words", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.TokenTTL = "1 week" }, true},
		{"tokenttl-duration", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.TokenTTL = "24h" }, false},
		{"boundclaimstype-string", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.BoundClaimsType = "string" }, false},
		{"boundclaimstype-non-enum", func(r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) { r.Spec.BoundClaimsType = "weird" }, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := validBase()
			r.Name = "t-" + tc.name
			tc.mutate(r)
			err := cl.Create(ctx, r)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{
					ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: ns},
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
