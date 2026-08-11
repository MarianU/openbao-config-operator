package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
)

// Shared timing knobs. 90s default covers worst-case reconcile under
// the operator's 5-minute periodic interval (cold path is on-event,
// not the periodic tick).
const (
	defaultEventuallyTimeout = 90 * time.Second
	defaultEventuallyPoll    = 2 * time.Second
)

type condReader interface {
	client.Object
	GetConditions() []metav1.Condition
}

// expectReady waits for the named CR to reach Ready=True (reason=Reconciled).
func expectReady(ctx context.Context, k8s client.Client, obj condReader, key types.NamespacedName) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(k8s.Get(ctx, key, obj)).To(Succeed())
		cond := findCond(obj.GetConditions(), "Ready")
		g.Expect(cond).NotTo(BeNil(), "Ready condition should be set on %s", key)
		g.Expect(cond.Status).To(Equal(metav1.ConditionTrue),
			"expected Ready=True on %s, got reason=%s message=%s",
			key, cond.Reason, cond.Message)
		g.Expect(cond.Reason).To(Equal("Reconciled"))
	}).WithTimeout(defaultEventuallyTimeout).WithPolling(defaultEventuallyPoll).Should(Succeed())
}

// expectReadyFalse waits for Ready=False; reason and msgSubstr are checked
// when non-empty.
func expectReadyFalse(ctx context.Context, k8s client.Client, obj condReader,
	key types.NamespacedName, reason, msgSubstr string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(k8s.Get(ctx, key, obj)).To(Succeed())
		cond := findCond(obj.GetConditions(), "Ready")
		g.Expect(cond).NotTo(BeNil(), "Ready condition should be set on %s", key)
		g.Expect(cond.Status).To(Equal(metav1.ConditionFalse),
			"expected Ready=False on %s, got Status=%s reason=%s msg=%s",
			key, cond.Status, cond.Reason, cond.Message)
		if reason != "" {
			g.Expect(cond.Reason).To(Equal(reason))
		}
		if msgSubstr != "" {
			g.Expect(cond.Message).To(ContainSubstring(msgSubstr))
		}
	}).WithTimeout(defaultEventuallyTimeout).WithPolling(defaultEventuallyPoll).Should(Succeed())
}

// expectGone waits for the CR to disappear from etcd (finalizer released).
func expectGone(ctx context.Context, k8s client.Client, obj client.Object, key types.NamespacedName) {
	GinkgoHelper()
	Eventually(func() bool {
		err := k8s.Get(ctx, key, obj)
		return k8serrors.IsNotFound(err)
	}).WithTimeout(defaultEventuallyTimeout).WithPolling(defaultEventuallyPoll).Should(BeTrue(),
		"CR %s should be gone after finalizer removal", key)
}

// deleteIfExists best-effort deletes a CR and waits for it to disappear.
// Run in BeforeAll so a prior crashed run doesn't poison the test.
func deleteIfExists(ctx context.Context, k8s client.Client, obj client.Object, key types.NamespacedName) {
	GinkgoHelper()
	_ = k8s.Delete(ctx, obj)
	Eventually(func() bool {
		err := k8s.Get(ctx, key, obj)
		return k8serrors.IsNotFound(err)
	}).WithTimeout(defaultEventuallyTimeout).WithPolling(defaultEventuallyPoll).Should(BeTrue(),
		"CR %s should be cleaned up before test starts", key)
}

// patchSpec applies a spec mutation via a merge patch. Update would race
// the controller's concurrent status writes — every reconcile bumps the
// resourceVersion, and an Update built on a stale Get fails with
// Conflict. MergeFrom skips the optimistic-lock check entirely: bao's
// drift-comparator is the source of truth for whether the spec change
// took effect, not the k8s Update succeeding.
func patchSpec[T client.Object](ctx context.Context, k8s client.Client,
	key types.NamespacedName, into T, mutate func(T)) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(k8s.Get(ctx, key, into)).To(Succeed())
		base := into.DeepCopyObject().(client.Object)
		mutate(into)
		g.Expect(k8s.Patch(ctx, into, client.MergeFrom(base))).To(Succeed())
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
}

// ensureAuthMethod creates an OpenBaoAuthMethod prereq at the given path and
// waits for Ready=True. Returns a teardown that the caller invokes from
// AfterAll. The teardown takes its own context because the BeforeAll's
// SpecContext is cancelled when BeforeAll returns; reusing it from AfterAll
// silently no-ops every k8s.Delete with a context-cancelled error.
func ensureAuthMethod(ctx context.Context, k8s client.Client, bao baoclient.Client,
	name, path, authType string) (teardown func(context.Context)) {
	GinkgoHelper()
	key := types.NamespacedName{Namespace: OperatorNS, Name: name}
	_ = bao.DisableAuthMount(ctx, path)
	deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoAuthMethod{
		ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: name},
	}, key)
	Expect(k8s.Create(ctx, &v1alpha1.OpenBaoAuthMethod{
		ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: name},
		Spec: v1alpha1.OpenBaoAuthMethodSpec{
			Path: path,
			Type: authType,
		},
	})).To(Succeed())
	expectReady(ctx, k8s, &v1alpha1.OpenBaoAuthMethod{}, key)
	return func(tdCtx context.Context) {
		_ = k8s.Delete(tdCtx, &v1alpha1.OpenBaoAuthMethod{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: name},
		})
		expectGone(tdCtx, k8s, &v1alpha1.OpenBaoAuthMethod{}, key)
		_ = bao.DisableAuthMount(tdCtx, path)
	}
}

// ensureSecretEngine creates an OpenBaoSecretEngine prereq at the given path
// and waits for Ready=True. spec carries the engine slot (KvV2, Transit, or
// PKI); the helper stamps Path on it. Returns a teardown closure that takes
// its own context (see ensureAuthMethod for the cancellation rationale).
func ensureSecretEngine(ctx context.Context, k8s client.Client, bao baoclient.Client,
	name, path string, spec v1alpha1.OpenBaoSecretEngineSpec) (teardown func(context.Context)) {
	GinkgoHelper()
	spec.Path = path
	key := types.NamespacedName{Namespace: OperatorNS, Name: name}
	_ = bao.DisableSecretEngineMount(ctx, path)
	deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{
		ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: name},
	}, key)
	Expect(k8s.Create(ctx, &v1alpha1.OpenBaoSecretEngine{
		ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: name},
		Spec:       spec,
	})).To(Succeed())
	expectReady(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{}, key)
	return func(tdCtx context.Context) {
		_ = k8s.Delete(tdCtx, &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: name},
		})
		expectGone(tdCtx, k8s, &v1alpha1.OpenBaoSecretEngine{}, key)
		_ = bao.DisableSecretEngineMount(tdCtx, path)
	}
}
