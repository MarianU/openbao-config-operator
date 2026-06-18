package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/test/utils"
)

var _ = Describe("OpenBaoCertAuthEngineConfig CR → OpenBao", Ordered, func() {
	const (
		amName    = "e2e-certcfg-mount"
		cfgName   = "e2e-certcfg"
		cfgBadCR  = "e2e-certcfg-invalid"
		mountPath = "e2e-cert-auth"
	)

	var (
		k8s        client.Client
		bao        baoclient.Client
		nn         types.NamespacedName
		amTeardown func(context.Context)
	)

	intPtr := func(i int) *int { return &i }

	BeforeAll(func(ctx SpecContext) {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: cfgName}

		amTeardown = ensureAuthMethod(ctx, k8s, bao, amName, mountPath, v1alpha1.AuthMethodTypeCert)
	})

	AfterAll(func(ctx SpecContext) { amTeardown(ctx) })

	It("creates a CertAuthConfig CR and writes the config to OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoCertAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		}, nn)

		cr := &v1alpha1.OpenBaoCertAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
			Spec: v1alpha1.OpenBaoCertAuthEngineConfigSpec{
				Path:          mountPath,
				OCSPCacheSize: intPtr(128),
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			cfg, err := bao.ReadCertAuthConfig(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cfg.OCSPCacheSize).NotTo(BeNil())
			g.Expect(*cfg.OCSPCacheSize).To(Equal(128))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoCertAuthEngineConfig{}, nn)
	})

	It("updates ocspCacheSize when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoCertAuthEngineConfig{},
			func(cur *v1alpha1.OpenBaoCertAuthEngineConfig) {
				cur.Spec.OCSPCacheSize = intPtr(256)
			})

		Eventually(func(g Gomega) {
			cfg, err := bao.ReadCertAuthConfig(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cfg.OCSPCacheSize).NotTo(BeNil())
			g.Expect(*cfg.OCSPCacheSize).To(Equal(256))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("removes the CR on delete without touching the bao config (IsDeletable=false)", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoCertAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoCertAuthEngineConfig{}, nn)

		// bao keeps the config; the controller doesn't roll it back.
		cfg, err := bao.ReadCertAuthConfig(ctx, mountPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
	})

	It("rejects an empty path", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoCertAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgBadCR},
			Spec: v1alpha1.OpenBaoCertAuthEngineConfigSpec{
				Path: "",
			},
		}
		err := k8s.Create(ctx, bad)
		Expect(err).To(HaveOccurred(), "CRD requires path MinLength=1")
	})
})
