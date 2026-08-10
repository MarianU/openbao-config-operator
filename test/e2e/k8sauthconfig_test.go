package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/test/utils"
)

var _ = Describe("OpenBaoKubernetesAuthEngineConfig CR → OpenBao", Ordered, func() {
	const (
		amName     = "e2e-k8scfg-mount"
		cfgName    = "e2e-k8scfg"
		cfgBadCR   = "e2e-k8scfg-invalid"
		secretName = "e2e-k8scfg-token-reviewer"
		mountPath  = "e2e-k8s-auth"
		// Sample JWT-shaped string. bao only checks that
		// token_reviewer_jwt is non-empty on write — it does NOT validate
		// signature or call TokenReview until login time.
		fakeJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlMmUifQ.signature"
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

		amTeardown = ensureAuthMethod(ctx, k8s, bao, amName, mountPath, v1alpha1.AuthMethodTypeKubernetes)

		// Token-reviewer JWT Secret.
		_ = k8s.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: secretName},
		})
		Expect(k8s.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: secretName},
			Data: map[string][]byte{
				"token": []byte(fakeJWT),
			},
		})).To(Succeed())
	})

	AfterAll(func(ctx SpecContext) {
		_ = k8s.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: secretName},
		})
		amTeardown(ctx)
	})

	It("creates a K8s auth config CR and writes the config to OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		}, nn)

		cr := &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
			Spec: v1alpha1.OpenBaoKubernetesAuthEngineConfigSpec{
				Path:           mountPath,
				KubernetesHost: "https://kubernetes.default.svc:443",
				TokenReviewerJwtRef: &v1alpha1.KubernetesTokenReviewerSecretRef{
					Name: secretName,
					Key:  "token",
				},
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			cfg, err := bao.ReadK8sAuthConfig(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cfg.KubernetesHost).To(Equal("https://kubernetes.default.svc:443"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{}, nn)
	})

	It("updates kubernetesHost when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{},
			func(cur *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
				cur.Spec.KubernetesHost = "https://kubernetes.default.svc:6443"
			})

		Eventually(func(g Gomega) {
			cfg, err := bao.ReadK8sAuthConfig(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cfg.KubernetesHost).To(Equal("https://kubernetes.default.svc:6443"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("removes the CR on delete without touching the bao config (IsDeletable=false)", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{}, nn)

		// bao /config has no DELETE; the config persists.
		cfg, err := bao.ReadK8sAuthConfig(ctx, mountPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.KubernetesHost).NotTo(BeEmpty())
	})

	It("rejects an empty kubernetesHost", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgBadCR},
			Spec: v1alpha1.OpenBaoKubernetesAuthEngineConfigSpec{
				Path:           mountPath,
				KubernetesHost: "",
			},
		}
		err := k8s.Create(ctx, bad)
		Expect(err).To(HaveOccurred(), "CRD requires KubernetesHost MinLength=1")
	})
})
