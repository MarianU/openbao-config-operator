package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/test/utils"
)

var _ = Describe("OpenBaoJWTOIDCAuthEngineConfig CR → OpenBao", Ordered, func() {
	const (
		amName    = "e2e-jwtcfg-mount"
		cfgName   = "e2e-jwtcfg"
		cfgBadCR  = "e2e-jwtcfg-invalid"
		mountPath = "e2e-jwt-cfg-auth"
	)

	var (
		k8s        client.Client
		bao        baoclient.Client
		nn         types.NamespacedName
		amTeardown func(context.Context)
	)

	BeforeAll(func(ctx SpecContext) {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: cfgName}

		amTeardown = ensureAuthMethod(ctx, k8s, bao, amName, mountPath, v1alpha1.AuthMethodTypeJWT)
	})

	AfterAll(func(ctx SpecContext) { amTeardown(ctx) })

	It("creates a JWTOIDC config CR and writes the config to OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		}, nn)

		// Use a static cert as the JWT validation pubkey. bao validates the
		// pubkey shape only — it doesn't fetch anything. JWKsURL /
		// OIDCDiscoveryURL both trigger live HTTP fetches at write time,
		// which would fail in an offline/air-gapped e2e environment.
		certPEM := string(generateSelfSignedCAPEM())

		cr := &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
			Spec: v1alpha1.OpenBaoJWTOIDCAuthEngineConfigSpec{
				Path:                 mountPath,
				JWTValidationPubkeys: []string{certPEM},
				BoundIssuer:          "https://issuer.example.com",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			cfg, err := bao.ReadJWTOIDCConfig(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cfg.JWTValidationPubkeys).NotTo(BeEmpty())
			g.Expect(cfg.BoundIssuer).To(Equal("https://issuer.example.com"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{}, nn)
	})

	It("updates boundIssuer when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{},
			func(cur *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) {
				cur.Spec.BoundIssuer = "https://issuer2.example.com"
			})

		Eventually(func(g Gomega) {
			cfg, err := bao.ReadJWTOIDCConfig(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cfg.BoundIssuer).To(Equal("https://issuer2.example.com"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("removes the CR on delete without touching the bao config (IsDeletable=false)", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{}, nn)

		cfg, err := bao.ReadJWTOIDCConfig(ctx, mountPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
	})

	It("rejects a spec missing all key-source fields", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgBadCR},
			Spec: v1alpha1.OpenBaoJWTOIDCAuthEngineConfigSpec{
				Path: mountPath,
				// No oidcDiscoveryUrl, jwksUrl, or jwtValidationPubkeys.
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{},
			types.NamespacedName{Namespace: OperatorNS, Name: cfgBadCR},
			"Invalid", "")
	})
})
