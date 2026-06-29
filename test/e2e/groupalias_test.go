package e2e

import (
	"context"
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

var _ = Describe("OpenBaoGroupAlias CR → OpenBao", Ordered, func() {
	const (
		amName       = "e2e-galias-mount"
		groupName    = "e2e-galias-group"
		aliasName    = "e2e-galias"
		aliasBadCR   = "e2e-galias-invalid"
		mountPath    = "e2e-galias-jwt"
		baoGroupName = "e2e-galias-group"
		baoAliasName = "alice@example.com"
	)

	var (
		k8s         client.Client
		bao         baoclient.Client
		nn          types.NamespacedName
		accessor    string
		canonicalID string
		amTeardown  func(context.Context)
	)

	BeforeAll(func(ctx SpecContext) {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: aliasName}

		// Prereq 1: an auth mount whose accessor the alias will reference.
		amTeardown = ensureAuthMethod(ctx, k8s, bao, amName, mountPath, v1alpha1.AuthMethodTypeJWT)

		Eventually(func(g Gomega) {
			var got v1alpha1.OpenBaoAuthMethod
			g.Expect(k8s.Get(ctx, types.NamespacedName{Namespace: OperatorNS, Name: amName}, &got)).To(Succeed())
			g.Expect(got.Status.MountAccessor).NotTo(BeEmpty())
			accessor = got.Status.MountAccessor
		}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())

		// Prereq 2: an external group whose id the alias will bind to.
		_ = bao.DeleteIdentityGroup(ctx, baoGroupName)
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupName},
		}, types.NamespacedName{Namespace: OperatorNS, Name: groupName})

		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupName},
			Spec: v1alpha1.OpenBaoGroupSpec{
				Name: baoGroupName,
				Type: "external",
			},
		})).To(Succeed())
		expectReady(ctx, k8s, &v1alpha1.OpenBaoGroup{},
			types.NamespacedName{Namespace: OperatorNS, Name: groupName})

		Eventually(func(g Gomega) {
			var got v1alpha1.OpenBaoGroup
			g.Expect(k8s.Get(ctx, types.NamespacedName{Namespace: OperatorNS, Name: groupName}, &got)).To(Succeed())
			g.Expect(got.Status.GroupID).NotTo(BeEmpty())
			canonicalID = got.Status.GroupID
		}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
	})

	AfterAll(func(ctx SpecContext) {
		_ = k8s.Delete(ctx, &v1alpha1.OpenBaoGroup{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: groupName},
		})
		expectGone(ctx, k8s, &v1alpha1.OpenBaoGroup{},
			types.NamespacedName{Namespace: OperatorNS, Name: groupName})
		_ = bao.DeleteIdentityGroup(ctx, baoGroupName)
		amTeardown(ctx)
	})

	It("creates a GroupAlias CR and sees the alias in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoGroupAlias{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: aliasName},
		}, nn)

		cr := &v1alpha1.OpenBaoGroupAlias{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: aliasName},
			Spec: v1alpha1.OpenBaoGroupAliasSpec{
				Name:          baoAliasName,
				MountAccessor: accessor,
				CanonicalGroupRef: &v1alpha1.OpenBaoGroupRef{
					Name: groupName,
				},
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			alias, err := bao.FindIdentityGroupAlias(ctx, baoAliasName, accessor)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(alias.Name).To(Equal(baoAliasName))
			g.Expect(alias.MountAccessor).To(Equal(accessor))
			g.Expect(alias.CanonicalID).To(Equal(canonicalID))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoGroupAlias{}, nn)
	})

	It("updates the alias name when the CR is patched", func(ctx SpecContext) {
		const newName = "alice2@example.com"
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoGroupAlias{}, func(cur *v1alpha1.OpenBaoGroupAlias) {
			cur.Spec.Name = newName
		})

		Eventually(func(g Gomega) {
			alias, err := bao.FindIdentityGroupAlias(ctx, newName, accessor)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(alias.Name).To(Equal(newName))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the alias when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoGroupAlias{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: aliasName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoGroupAlias{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.FindIdentityGroupAlias(ctx, "alice2@example.com", accessor)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects a spec with neither canonicalId nor canonicalGroupRef", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoGroupAlias{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: aliasBadCR},
			Spec: v1alpha1.OpenBaoGroupAliasSpec{
				Name:          "bad-alias",
				MountAccessor: accessor,
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoGroupAlias{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: aliasBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoGroupAlias{},
			types.NamespacedName{Namespace: OperatorNS, Name: aliasBadCR},
			"Invalid", "")
	})
})
