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

var _ = Describe("OpenBaoSecretEngine CR → OpenBao", Ordered, func() {
	const (
		seName  = "e2e-secret-engine"
		seBadCR = "e2e-secret-engine-invalid"
		path    = "e2e-kv"
	)

	var (
		k8s client.Client
		bao baoclient.Client
		nn  types.NamespacedName
	)

	BeforeAll(func() {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: seName}
	})

	It("creates a SecretEngine CR and sees the kv-v2 mount in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: seName},
		}, nn)
		// Cleanup any leftover bao-side mount from a prior run.
		_ = bao.DisableSecretEngineMount(ctx, path)

		cr := &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: seName},
			Spec: v1alpha1.OpenBaoSecretEngineSpec{
				Path:        path,
				Description: "e2e kv mount",
				KvV2:        &v1alpha1.KvV2Spec{},
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// No DeferCleanup here — DeferCleanup inside an It fires when that
		// It completes, which would delete the CR between create and update
		// specs. The "deletes" spec below owns cleanup; if a prior spec
		// fails, the next run's BeforeAll deleteIfExists handles leftovers.

		Eventually(func(g Gomega) {
			mount, err := bao.GetSecretEngineMount(ctx, path)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(mount.Type).To(Equal("kv"))
			g.Expect(mount.Options["version"]).To(Equal("2"))
			g.Expect(mount.Description).To(Equal("e2e kv mount"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{}, nn)
	})

	It("updates the mount description when spec.description changes", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoSecretEngine{}, func(cur *v1alpha1.OpenBaoSecretEngine) {
			cur.Spec.Description = "e2e kv mount updated"
		})

		Eventually(func(g Gomega) {
			mount, err := bao.GetSecretEngineMount(ctx, path)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(mount.Description).To(Equal("e2e kv mount updated"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("retains the mount when the CR is deleted (default deletionPolicy)", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: seName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{}, nn)

		// Retain is the default: the mount must survive the CR.
		mount, err := bao.GetSecretEngineMount(ctx, path)
		Expect(err).NotTo(HaveOccurred(),
			"mount must be retained after CR delete under the default policy")
		Expect(mount.Type).To(Equal("kv"))
	})

	It("adopts the retained mount and deletes it when deletionPolicy=Delete", func(ctx SpecContext) {
		// Same path + same description as the retained mount, so the
		// re-created CR adopts it without a write — the documented
		// recovery/teardown flow for orphans.
		cr := &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: seName},
			Spec: v1alpha1.OpenBaoSecretEngineSpec{
				Path:           path,
				Description:    "e2e kv mount updated",
				KvV2:           &v1alpha1.KvV2Spec{},
				DeletionPolicy: v1alpha1.DeletionPolicyDelete,
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		expectReady(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{}, nn)

		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: seName},
		})).To(Succeed())
		expectGone(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.GetSecretEngineMount(ctx, path)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete with deletionPolicy=Delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects a spec that sets no engine slot", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: seBadCR},
			Spec: v1alpha1.OpenBaoSecretEngineSpec{
				Path: "e2e-bad",
			},
		}
		// The CRD's XValidation may catch this at admission; if so, Create
		// returns an Invalid error and we never reach the reconciler. The
		// IsValid() path also catches it at the reconciler. Either is fine.
		err := k8s.Create(ctx, bad)
		if err != nil {
			Expect(err.Error()).To(ContainSubstring("exactly one of"))
			return
		}
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoSecretEngine{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: seBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoSecretEngine{},
			types.NamespacedName{Namespace: OperatorNS, Name: seBadCR},
			"Invalid", "exactly one of")
	})
})
