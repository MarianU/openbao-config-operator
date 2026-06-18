package e2e

import (
	"errors"
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

var _ = Describe("OpenBaoAuthMethod CR → OpenBao", Ordered, func() {
	const (
		amName  = "e2e-auth-method"
		amBadCR = "e2e-auth-method-invalid"
		path    = "e2e-jwt"
		// jwt is a safe, mountable auth-method type that does not depend
		// on external services to enable. Avoid "kubernetes" because the
		// suite's other tests share that mount.
		amType = v1alpha1.AuthMethodTypeJWT
	)

	var (
		k8s client.Client
		bao baoclient.Client
		nn  types.NamespacedName
	)

	BeforeAll(func() {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: amName}
	})

	It("creates an AuthMethod CR and sees the auth mount in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoAuthMethod{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: amName},
		}, nn)
		_ = bao.DisableAuthMount(ctx, path)

		cr := &v1alpha1.OpenBaoAuthMethod{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: amName},
			Spec: v1alpha1.OpenBaoAuthMethodSpec{
				Path:        path,
				Type:        amType,
				Description: "e2e jwt mount",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			am, err := bao.GetAuthMethod(ctx, path)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(am.Type).To(Equal(amType))
			g.Expect(am.Description).To(Equal("e2e jwt mount"))
			g.Expect(am.Accessor).NotTo(BeEmpty(), "bao stamps the accessor at mount time")
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoAuthMethod{}, nn)

		var got v1alpha1.OpenBaoAuthMethod
		Expect(k8s.Get(ctx, nn, &got)).To(Succeed())
		Expect(got.Status.MountAccessor).NotTo(BeEmpty(),
			"controller should stamp status.mountAccessor after a successful reconcile")
	})

	It("updates description when spec.description changes", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoAuthMethod{}, func(cur *v1alpha1.OpenBaoAuthMethod) {
			cur.Spec.Description = "e2e jwt mount updated"
		})

		Eventually(func(g Gomega) {
			am, err := bao.GetAuthMethod(ctx, path)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(am.Description).To(Equal("e2e jwt mount updated"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("disables the auth mount when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoAuthMethod{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: amName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoAuthMethod{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.GetAuthMethod(ctx, path)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects an unknown auth-method type at admission", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoAuthMethod{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: amBadCR},
			Spec: v1alpha1.OpenBaoAuthMethodSpec{
				Path: "e2e-bad-auth",
				Type: "foobar",
			},
		}
		// CRD-level Enum should reject this at admission.
		err := k8s.Create(ctx, bad)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unsupported value"))
	})
})
