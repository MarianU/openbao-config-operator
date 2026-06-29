package openbaopkisecretengineconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
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

// TestCRDValidation_OpenBaoPKIConfig_RejectsInvalid drives the kubebuilder
// markers the controller relies on through admission: Required, Pattern, Enum,
// MinLength, MaxLength — for the upstream-aligned field set (type root +
// intermediate, flat subject, SANs, name constraints, signing refs).
func TestCRDValidation_OpenBaoPKIConfig_RejectsInvalid(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()

	const ns = "default"
	validBase := func() *v1alpha1.OpenBaoPKISecretEngineConfig {
		c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
		c.Namespace = ns
		c.Spec.Path = "pki"
		c.Spec.Type = "root"
		c.Spec.CommonName = testCommonName
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
			hint:    "canonical valid root spec must admit",
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
			name:    "type-intermediate-accepted",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.Type = v1alpha1.PKITypeIntermediate },
			invalid: false,
			hint:    "Enum on spec.type now admits intermediate (IsValid enforces a signing model, not the CRD)",
		},
		{
			name:    "type-bogus-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.Type = "bogus" },
			invalid: true,
			hint:    "Enum=root;intermediate on spec.type",
		},
		{
			name:    "keyType-dsa-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.KeyType = "dsa" },
			invalid: true,
			hint:    "Enum=rsa;ec on spec.keyType",
		},
		{
			name:    "keyType-ed25519-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.KeyType = "ed25519" },
			invalid: true,
			hint:    "Enum tightened to rsa;ec — ed25519 dropped to match upstream",
		},
		{
			name:    "format-non-enum-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.Format = "jpeg" },
			invalid: true,
			hint:    "Enum=pem;pem_bundle;der on spec.format",
		},
		{
			name:    "privateKeyType-non-enum-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.PrivateKeyType = "magic" },
			invalid: true,
			hint:    "Enum=internal;exported on spec.privateKeyType",
		},
		{
			name:    "openbaoNamespace-uppercase-rejected",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.OpenBaoNamespace = "ACME/" },
			invalid: true,
			hint:    "Pattern on spec.openbaoNamespace rejects uppercase",
		},
		{
			name:    "path-pattern-rejected-leading-slash",
			mutate:  func(c *v1alpha1.OpenBaoPKISecretEngineConfig) { c.Spec.Path = "/pki" },
			invalid: true,
			hint:    "Pattern on spec.path rejects leading slash",
		},
		{
			name: "intermediate-internalSign-and-rich-fields-accepted",
			mutate: func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
				c.Spec.Type = v1alpha1.PKITypeIntermediate
				c.Spec.InternalSign = &v1alpha1.PKIInternalSign{Name: "pki-root"}
				c.Spec.TTL = metav1.Duration{Duration: 8760 * time.Hour}
				c.Spec.MaxPathLength = 0
				c.Spec.AltNames = "a.example.com,b.example.com"
				c.Spec.IPSans = "10.0.0.1"
				c.Spec.URISans = "spiffe://example/svc"
				c.Spec.PermittedDnsDomains = []string{"svc.cluster.local"}
				c.Spec.OU = "Platform"
				c.Spec.Organization = "Stakater"
				c.Spec.Country = "US"
				c.Spec.SerialNumber = "12345"
				c.Spec.CRLExpiry = metav1.Duration{Duration: 72 * time.Hour}
				c.Spec.CRLDisable = true
			},
			invalid: false,
			hint:    "flat subject + SANs + name constraints + CRL config + internalSign admit",
		},
		{
			name: "intermediate-externalSign-default-certificateKey-accepted",
			mutate: func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
				c.Spec.Type = v1alpha1.PKITypeIntermediate
				c.Spec.ExternalSignSecret = &corev1.LocalObjectReference{Name: "signed-ca"}
				// certificateKey omitted → defaults to tls.crt.
			},
			invalid: false,
			hint:    "externalSignSecret + defaulted certificateKey admit",
		},
		{
			name: "intermediate-internalSign-cross-namespace-accepted",
			mutate: func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
				c.Spec.Type = v1alpha1.PKITypeIntermediate
				c.Spec.InternalSign = &v1alpha1.PKIInternalSign{Name: "pki-platform", OpenBaoNamespace: "platform/"}
			},
			invalid: false,
			hint:    "internalSign.openbaoNamespace admits a valid namespace pattern",
		},
		{
			name: "intermediate-internalSign-missing-name-rejected",
			mutate: func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
				c.Spec.Type = v1alpha1.PKITypeIntermediate
				c.Spec.InternalSign = &v1alpha1.PKIInternalSign{OpenBaoNamespace: "platform/"}
			},
			invalid: true,
			hint:    "internalSign.name is Required (MinLength=1)",
		},
		{
			name: "intermediate-internalSign-bad-namespace-rejected",
			mutate: func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
				c.Spec.Type = v1alpha1.PKITypeIntermediate
				c.Spec.InternalSign = &v1alpha1.PKIInternalSign{Name: "pki-platform", OpenBaoNamespace: "BadNS/"}
			},
			invalid: true,
			hint:    "internalSign.openbaoNamespace Pattern rejects uppercase",
		},
		{
			name: "publishCABundleConfigMap-accepted",
			mutate: func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
				c.Spec.PublishCABundleConfigMap = caBundleCMName
			},
			invalid: false,
			hint:    "valid RFC1123 ConfigMap name admits",
		},
		{
			name: "publishCABundleConfigMap-bad-name-rejected",
			mutate: func(c *v1alpha1.OpenBaoPKISecretEngineConfig) {
				c.Spec.PublishCABundleConfigMap = "Bad_Name"
			},
			invalid: true,
			hint:    "Pattern on publishCABundleConfigMap rejects underscore/uppercase",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validBase()
			// Lowercase: metadata.name must be RFC 1123, while case names are
			// descriptive (camelCase). Without this, an uppercase case name
			// gets rejected on the NAME, masking whether the marker fired.
			c.Name = "t-" + strings.ToLower(tc.name)
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

// TestCRDValidation_OpenBaoPKIConfig_DefaultsCertificateKey confirms the
// kubebuilder default lands on the externalSignSecret certificateKey.
func TestCRDValidation_OpenBaoPKIConfig_DefaultsCertificateKey(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()
	const ns = "default"

	c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
	c.Namespace = ns
	c.Name = "t-default-certkey"
	c.Spec.Path = "pki-ck"
	c.Spec.Type = v1alpha1.PKITypeIntermediate
	c.Spec.CommonName = "Test Intermediate"
	c.Spec.ExternalSignSecret = &corev1.LocalObjectReference{Name: "signed-ca"}
	require.NoError(t, cl.Create(ctx, c))
	t.Cleanup(func() {
		_ = cl.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: ns},
		})
	})

	var got v1alpha1.OpenBaoPKISecretEngineConfig
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: c.Name}, &got))
	require.Equal(t, "tls.crt", got.Spec.CertificateKey, "certificateKey must default to tls.crt")
}

// TestCRDValidation_OpenBaoPKIConfig_DefaultsType confirms an omitted
// spec.type defaults to root at admission.
func TestCRDValidation_OpenBaoPKIConfig_DefaultsType(t *testing.T) {
	cl := newEnvtestClient(t)
	ctx := context.Background()
	const ns = "default"

	c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
	c.Namespace = ns
	c.Name = "t-default-type"
	c.Spec.Path = "pki-dt"
	c.Spec.CommonName = testCommonName
	require.NoError(t, cl.Create(ctx, c))
	t.Cleanup(func() {
		_ = cl.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: ns},
		})
	})

	var got v1alpha1.OpenBaoPKISecretEngineConfig
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: c.Name}, &got))
	require.Equal(t, "root", got.Spec.Type, "spec.type must default to root")
}
