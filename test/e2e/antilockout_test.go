package e2e

import (
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

// The deny stanzas in hack/e2e/openbao/operator-policy.hcl keep a CR from
// reaching the mount the operator logs in through or the policy it carries.
// Nothing in the reconcilers enforces that — bao's policy evaluation is the
// guard — so it can only be exercised against a live server, and only once
// the operator authenticates with operator-manage (`make
// openbao-bootstrap-auth`). The harness client holds the wider
// obx-e2e-manage policy, and is used here to read bao and to repair it.
var _ = Describe("anti-lockout guard: bootstrap-owned bao objects", Ordered, func() {
	const (
		// Bootstrap defaults, matching the literals the deny stanzas use.
		operatorPolicy    = "operator-manage"
		operatorAuthMount = "k8s-operator"

		selfPolicyCR = "e2e-antilockout-self-policy"
		selfMountCR  = "e2e-antilockout-self-mount"
		canaryCR     = "e2e-antilockout-canary"

		canaryBody = `path "secret/data/e2e-antilockout/*" { capabilities = ["read"] }`
	)

	var (
		k8s client.Client
		bao baoclient.Client
	)

	BeforeAll(func() {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
	})

	It("refuses a Policy CR that claims the operator's own policy", func(ctx SpecContext) {
		nn := types.NamespacedName{Namespace: OperatorNS, Name: selfPolicyCR}
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: selfPolicyCR},
		}, nn)

		before, err := bao.GetPolicy(ctx, operatorPolicy)
		Expect(err).NotTo(HaveOccurred(),
			"the operator's policy must exist — run `make openbao-bootstrap-auth` first")
		Expect(before).NotTo(BeEmpty())

		// A comment-only addition: if the deny ever regressed, the write lands
		// and this spec fails, but the operator's effective permissions are
		// unchanged either way. A failure here cannot escalate the credential
		// the rest of the suite runs under.
		cr := &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: selfPolicyCR},
			Spec: v1alpha1.OpenBaoPolicySpec{
				Name:   operatorPolicy,
				Policy: before + "\n# e2e anti-lockout probe\n",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: selfPolicyCR},
			})
			expectGone(ctx, k8s, &v1alpha1.OpenBaoPolicy{}, nn)
			// A CR that did claim the policy deletes it bao-side on teardown,
			// so repair unconditionally rather than only on failure.
			Expect(bao.UpsertPolicy(ctx, operatorPolicy, before)).To(Succeed())
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoPolicy{}, nn, "Forbidden", "permission denied")

		after, err := bao.GetPolicy(ctx, operatorPolicy)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "the operator's own policy must be untouched")
	})

	It("refuses a K8s auth config CR that claims the operator's own login mount", func(ctx SpecContext) {
		nn := types.NamespacedName{Namespace: OperatorNS, Name: selfMountCR}
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: selfMountCR},
		}, nn)

		before, err := bao.ReadK8sAuthConfig(ctx, operatorAuthMount)
		Expect(err).NotTo(HaveOccurred(),
			"the operator's login mount must exist — run `make openbao-bootstrap-auth` first")
		Expect(before.KubernetesHost).NotTo(BeEmpty())

		// Not the API server: if this landed, every subsequent operator login
		// would fail TokenReview.
		cr := &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: selfMountCR},
			Spec: v1alpha1.OpenBaoKubernetesAuthEngineConfigSpec{
				Path:           operatorAuthMount,
				KubernetesHost: "https://not-the-apiserver.invalid:443",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: selfMountCR},
			})
			expectGone(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{}, nn)
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthEngineConfig{}, nn,
			"Forbidden", "permission denied")

		after, err := bao.ReadK8sAuthConfig(ctx, operatorAuthMount)
		Expect(err).NotTo(HaveOccurred())
		Expect(after.KubernetesHost).To(Equal(before.KubernetesHost),
			"the operator's login mount config must be untouched")
	})

	It("still reconciles ordinary CRs after the denied attempts", func(ctx SpecContext) {
		nn := types.NamespacedName{Namespace: OperatorNS, Name: canaryCR}
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: canaryCR},
		}, nn)

		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: canaryCR},
			Spec:       v1alpha1.OpenBaoPolicySpec{Policy: canaryBody},
		})).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: canaryCR},
			})
			expectGone(ctx, k8s, &v1alpha1.OpenBaoPolicy{}, nn)
		})

		expectReady(ctx, k8s, &v1alpha1.OpenBaoPolicy{}, nn)

		Eventually(func(g Gomega) {
			body, err := bao.GetPolicy(ctx, canaryCR)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(body).To(Equal(canaryBody))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})
})
