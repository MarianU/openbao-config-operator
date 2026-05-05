package openbaokubernetesauthengineconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestCRDValidation_OpenBaoKubernetesAuthEngineConfig(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()
	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoKubernetesAuthEngineConfig {
		c := &v1alpha1.OpenBaoKubernetesAuthEngineConfig{}
		c.Namespace = ns
		c.Spec.Path = "kubernetes"
		c.Spec.KubernetesHost = "https://kubernetes.default.svc:443"
		return c
	}
	cases := []struct {
		name    string
		mutate  func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig)
		invalid bool
	}{
		{"valid-baseline", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {}, false},
		{"empty-path-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) { c.Spec.Path = "" }, true},
		{"empty-host-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) { c.Spec.KubernetesHost = "" }, true},
		{"path-with-uppercase-allowed", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.Path = "Kubernetes"
		}, false},
		{"path-with-leading-slash-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.Path = "/kubernetes"
		}, true},
		{"path-with-space-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.Path = "kube rnetes"
		}, true},
		// Locks in the anchored Pattern's left edge — without ^…$
		// anchors, OpenAPI v3 substring match would accept "_kube"
		// (substring "kube" matches the unanchored pattern).
		{"path-with-leading-underscore-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.Path = "_kubernetes"
		}, true},
		{"path-too-long-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.Path = strings.Repeat("a", 129)
		}, true},
		{"path-128-chars-accepted", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.Path = strings.Repeat("a", 128)
		}, false},
		{"openbaonamespace-uppercase-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.OpenBaoNamespace = "ACME/"
		}, true},
		{"openbaonamespace-nested-allowed", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.OpenBaoNamespace = "acme/sub/"
		}, false},
		{"jwt-ref-empty-name-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.TokenReviewerJwtRef = &v1alpha1.KubernetesTokenReviewerSecretRef{Name: ""}
		}, true},
		{"jwt-ref-with-name-allowed", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.TokenReviewerJwtRef = &v1alpha1.KubernetesTokenReviewerSecretRef{Name: "k8s-token"}
		}, false},
		{"ca-ref-empty-name-rejected", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.KubernetesCaCertRef = &v1alpha1.KubernetesCaSecretRef{Name: ""}
		}, true},
		{"ca-ref-with-name-allowed", func(c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
			c.Spec.KubernetesCaCertRef = &v1alpha1.KubernetesCaSecretRef{Name: "k8s-ca"}
		}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := validBase()
			c.Name = "t-" + tc.name
			tc.mutate(c)
			err := cl.Create(ctx, c)
			t.Cleanup(func() {
				_ = cl.Delete(ctx, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
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
