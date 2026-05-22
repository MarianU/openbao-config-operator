package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	"github.com/stakater-ab/mto-extension-openbao/test/utils"
)

// Drift correction is covered in envtest
// (internal/controller/openbaopolicy/openbaopolicy_controller_test.go:TestOpenBaoPolicy_DriftCorrection)
// rather than e2e — the operator's 5-minute periodic interval makes an e2e
// drift spec painful, and the behaviour is pure Go that doesn't need a live
// cluster to exercise.

var _ = Describe("OpenBaoPolicy CR → OpenBao", Ordered, func() {
	const (
		policyName = "e2e-policy-secret-reader"
		initBody   = `path "secret/data/e2e-public/*" { capabilities = ["read"] }`
		editBody   = `path "secret/data/e2e-public/*" { capabilities = ["read", "list"] }`
	)

	var k8s client.Client
	var bao *utils.BaoClient

	BeforeAll(func() {
		k8s = utils.GetK8sClient()
		bao = utils.NewBaoClientFromEnv()
	})

	It("creates a Policy CR and sees the policy in OpenBao", func(ctx SpecContext) {
		By("cleaning up any leftover Policy from a previous run")
		_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: OperatorNS},
		})
		Eventually(func() bool {
			var p v1alpha1.OpenBaoPolicy
			err := k8s.Get(ctx, types.NamespacedName{Namespace: OperatorNS, Name: policyName}, &p)
			return k8serrors.IsNotFound(err)
		}).WithTimeout(30 * time.Second).WithPolling(1 * time.Second).Should(BeTrue())

		// Also scrub any lingering bao-side policy so the "create" assertion is meaningful.
		By("cleaning up any leftover bao-side policy")
		Eventually(func() bool {
			_, err := bao.GetPolicy(ctx, policyName)
			return err != nil && strings.Contains(err.Error(), "not found")
		}).WithTimeout(10*time.Second).WithPolling(1*time.Second).Should(BeTrue(),
			"bao-side policy should not exist before the test creates the CR")

		By("creating the Policy CR")
		cr := &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: OperatorNS},
			Spec: v1alpha1.OpenBaoPolicySpec{
				Policy: initBody,
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		DeferCleanup(func() {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: OperatorNS},
			})
		})

		By("waiting for the bao-side policy to match spec.policy")
		Eventually(func(g Gomega) {
			body, err := bao.GetPolicy(ctx, policyName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(body).To(Equal(initBody))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		By("observing Ready=True on the CR status")
		Eventually(func(g Gomega) {
			var got v1alpha1.OpenBaoPolicy
			g.Expect(k8s.Get(ctx, types.NamespacedName{Namespace: OperatorNS, Name: policyName}, &got)).To(Succeed())
			cond := findCond(got.Status.Conditions, "Ready")
			g.Expect(cond).NotTo(BeNil(), "Ready condition should be set")
			g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(cond.Reason).To(Equal("Reconciled"))
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("updates the policy when the CR spec changes", func(ctx SpecContext) {
		By("patching spec.policy")
		Eventually(func(g Gomega) {
			var cur v1alpha1.OpenBaoPolicy
			g.Expect(k8s.Get(ctx, types.NamespacedName{Namespace: OperatorNS, Name: policyName}, &cur)).To(Succeed())
			cur.Spec.Policy = editBody
			g.Expect(k8s.Update(ctx, &cur)).To(Succeed())
		}).WithTimeout(10 * time.Second).Should(Succeed())

		By("waiting for bao-side body to reflect the edit")
		Eventually(func(g Gomega) {
			body, err := bao.GetPolicy(ctx, policyName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(body).To(Equal(editBody))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the policy when the CR is deleted", func(ctx SpecContext) {
		By("deleting the Policy CR")
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: OperatorNS},
		})).To(Succeed())

		By("waiting for the CR to disappear (finalizer releases after bao delete)")
		Eventually(func() bool {
			var p v1alpha1.OpenBaoPolicy
			err := k8s.Get(ctx, types.NamespacedName{Namespace: OperatorNS, Name: policyName}, &p)
			return k8serrors.IsNotFound(err)
		}).WithTimeout(60*time.Second).WithPolling(2*time.Second).Should(BeTrue(),
			"CR should be gone from etcd after finalizer removal")

		By("verifying the bao-side policy is gone")
		Eventually(func(g Gomega) {
			_, err := bao.GetPolicy(ctx, policyName)
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("not found"))
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("surfaces a condition when accessor templating is used", func(ctx SpecContext) {
		tmplName := policyName + "-tmpl"

		// Scrub any leftover from a prior run before Create; otherwise we
		// hit AlreadyExists when a previous failed run left this CR in
		// Terminating state.
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: tmplName, Namespace: OperatorNS},
		}, types.NamespacedName{Namespace: OperatorNS, Name: tmplName})

		By("applying a Policy with a ${auth/.../@accessor} placeholder")
		cr := &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: tmplName, Namespace: OperatorNS},
			Spec: v1alpha1.OpenBaoPolicySpec{
				Policy: `path "x" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`,
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		DeferCleanup(func() {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: tmplName, Namespace: OperatorNS},
			})
		})

		By("expecting Ready=False with a user-facing placeholder-rejection message")
		Eventually(func(g Gomega) {
			var got v1alpha1.OpenBaoPolicy
			g.Expect(k8s.Get(ctx, types.NamespacedName{Namespace: OperatorNS, Name: tmplName}, &got)).To(Succeed())
			cond := findCond(got.Status.Conditions, "Ready")
			g.Expect(cond).NotTo(BeNil(), "Ready condition should be set")
			g.Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(cond.Message).To(ContainSubstring("placeholder"))
			g.Expect(cond.Message).To(ContainSubstring("bao auth list"))
			// Must not leak internal roadmap jargon to end users.
			g.Expect(strings.ToLower(cond.Message)).NotTo(ContainSubstring("story 6"))
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		By("expecting no bao-side policy was written")
		_, err := bao.GetPolicy(ctx, tmplName)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"),
			fmt.Sprintf("templating-rejected CR should not create a bao policy: %v", err))
	})
})

func findCond(conds []metav1.Condition, typ string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == typ {
			return &conds[i]
		}
	}
	return nil
}
