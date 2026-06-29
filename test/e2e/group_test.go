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

var _ = Describe("OpenBaoGroup CR → OpenBao", Ordered, func() {
	const (
		groupName    = "e2e-group"
		groupBadCR   = "e2e-group-invalid"
		baoGroupName = "e2e-group"
	)

	var (
		k8s client.Client
		bao baoclient.Client
		nn  types.NamespacedName
	)

	BeforeAll(func() {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: groupName}
	})

	It("creates a Group CR and sees the group in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupName},
		}, nn)
		_ = bao.DeleteIdentityGroup(ctx, baoGroupName)

		cr := &v1alpha1.OpenBaoGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupName},
			Spec: v1alpha1.OpenBaoGroupSpec{
				Name:     baoGroupName,
				Type:     "internal",
				Policies: []string{"default"},
				Metadata: map[string]string{"team": "e2e"},
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			grp, err := bao.ReadIdentityGroup(ctx, baoGroupName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(grp.Type).To(Equal("internal"))
			g.Expect(grp.Policies).To(ContainElement("default"))
			g.Expect(grp.Metadata["team"]).To(Equal("e2e"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoGroup{}, nn)

		var got v1alpha1.OpenBaoGroup
		Expect(k8s.Get(ctx, nn, &got)).To(Succeed())
		Expect(got.Status.GroupID).NotTo(BeEmpty(),
			"controller should stamp status.groupId on first create")
	})

	It("updates policies when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoGroup{}, func(cur *v1alpha1.OpenBaoGroup) {
			cur.Spec.Policies = []string{"default", "secret-reader"}
		})

		Eventually(func(g Gomega) {
			grp, err := bao.ReadIdentityGroup(ctx, baoGroupName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(grp.Policies).To(ConsistOf("default", "secret-reader"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the group when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoGroup{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.ReadIdentityGroup(ctx, baoGroupName)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects an external group with member ids", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupBadCR},
			Spec: v1alpha1.OpenBaoGroupSpec{
				Name:            "e2e-group-bad",
				Type:            "external",
				MemberEntityIds: []string{"00000000-0000-0000-0000-000000000000"},
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoGroup{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoGroup{},
			types.NamespacedName{Namespace: OperatorNS, Name: groupBadCR},
			"Invalid", "external")
	})
})
