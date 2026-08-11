package e2e

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/test/utils"
)

var _ = Describe("OpenBaoNamespace CR → OpenBao", Ordered, func() {
	const (
		nsName  = "e2e-ns"
		nsBadCR = "e2e-ns-invalid"
		baoNS   = "e2e-ns"
	)

	var (
		k8s client.Client
		bao baoclient.Client
		nn  types.NamespacedName
	)

	BeforeAll(func() {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: nsName}
	})

	It("creates a Namespace CR and sees the namespace in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoNamespace{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: nsName},
		}, nn)
		_ = bao.DeleteNamespace(ctx, baoNS)

		cr := &v1alpha1.OpenBaoNamespace{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: nsName},
			Spec: v1alpha1.OpenBaoNamespaceSpec{
				Name: baoNS,
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			ns, err := bao.GetNamespace(ctx, baoNS)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ns.ID).NotTo(BeEmpty(), "bao stamps an id at create time")
			g.Expect(ns.Path).To(ContainSubstring(baoNS))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoNamespace{}, nn)
	})

	// OpenBaoNamespace has no mutable spec — IsEquivalentToDesiredState
	// returns true unconditionally. Skip the update case; create→delete
	// covers the lifecycle.

	It("retains the namespace when the CR is deleted (default deletionPolicy)", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoNamespace{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: nsName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoNamespace{}, nn)

		// Retain is the default: bao's namespace delete cascades through
		// everything inside it, so the namespace must survive the CR.
		ns, err := bao.GetNamespace(ctx, baoNS)
		Expect(err).NotTo(HaveOccurred(),
			"bao namespace must be retained after CR delete under the default policy")
		Expect(ns.ID).NotTo(BeEmpty())
	})

	It("adopts the retained namespace and deletes it when deletionPolicy=Delete", func(ctx SpecContext) {
		cr := &v1alpha1.OpenBaoNamespace{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: nsName},
			Spec: v1alpha1.OpenBaoNamespaceSpec{
				Name:           baoNS,
				DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		expectReady(ctx, k8s, &v1alpha1.OpenBaoNamespace{}, nn)

		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoNamespace{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: nsName},
		})).To(Succeed())
		expectGone(ctx, k8s, &v1alpha1.OpenBaoNamespace{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.GetNamespace(ctx, baoNS)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete with deletionPolicy=Delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects a reserved namespace name", func(ctx SpecContext) {
		// "root" is hard-rejected by IsValid (CRD pattern allows it but
		// the controller refuses). Bao would also reject it; failing at
		// IsValid is the explicit cheaper path.
		bad := &v1alpha1.OpenBaoNamespace{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: nsBadCR},
			Spec: v1alpha1.OpenBaoNamespaceSpec{
				Name: "root",
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoNamespace{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: nsBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoNamespace{},
			types.NamespacedName{Namespace: OperatorNS, Name: nsBadCR},
			"Invalid", "reserved")
	})
})
