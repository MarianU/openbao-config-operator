package e2e

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/test/utils"
)

var _ = Describe("OpenBaoKubernetesAuthRole CR → OpenBao", Ordered, func() {
	const (
		amName       = "e2e-k8srole-mount"
		roleName     = "e2e-k8s-role"
		roleBadCR    = "e2e-k8s-role-invalid"
		mountPath    = "e2e-k8s-role-auth"
		targetNSName = "e2e-k8srole-target-ns"
		baoRole      = "e2e-k8s-role"
		targetSAName = "default"
		targetPolicy = "default"
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
		nn = types.NamespacedName{Namespace: OperatorNS, Name: roleName}

		amTeardown = ensureAuthMethod(ctx, k8s, bao, amName, mountPath, v1alpha1.AuthMethodTypeKubernetes)

		// Target namespace for the role's bound_service_account_namespaces.
		// May already exist (test re-run) — ignore Already-Exists.
		if err := k8s.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: targetNSName},
		}); err != nil && !k8serrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	AfterAll(func(ctx SpecContext) {
		amTeardown(ctx)
		_ = k8s.Delete(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: targetNSName},
		})
	})

	It("creates a KubernetesAuthRole CR and sees the role in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		}, nn)

		cr := &v1alpha1.OpenBaoKubernetesAuthRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
			Spec: v1alpha1.OpenBaoKubernetesAuthRoleSpec{
				Path: mountPath,
				Name: baoRole,
				VRole: v1alpha1.VRole{
					TargetServiceAccounts: []string{targetSAName},
					Policies:              []string{targetPolicy},
					TokenTTL:              "1h",
				},
				TargetNamespaces: v1alpha1.TargetNamespaceConfig{
					TargetNamespaces: []string{targetNSName},
				},
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			role, err := bao.GetK8sRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.BoundServiceAccountNames).To(ContainElement(targetSAName))
			g.Expect(role.BoundServiceAccountNamespaces).To(ContainElement(targetNSName))
			g.Expect(role.Policies).To(ContainElement(targetPolicy))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthRole{}, nn)
	})

	It("updates policies when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoKubernetesAuthRole{},
			func(cur *v1alpha1.OpenBaoKubernetesAuthRole) {
				// Add a distinct policy (Policies is `+listType=set`; CRD
				// rejects duplicates of targetPolicy).
				cur.Spec.Policies = []string{targetPolicy, "secret-reader"}
			})

		Eventually(func(g Gomega) {
			role, err := bao.GetK8sRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.Policies).To(ContainElement("secret-reader"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the role when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoKubernetesAuthRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthRole{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.GetK8sRole(ctx, mountPath, baoRole)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects a spec with both targetNamespaces and selector set", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoKubernetesAuthRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			Spec: v1alpha1.OpenBaoKubernetesAuthRoleSpec{
				Path: mountPath,
				Name: "e2e-k8s-role-bad",
				VRole: v1alpha1.VRole{
					TargetServiceAccounts: []string{targetSAName},
					Policies:              []string{targetPolicy},
				},
				TargetNamespaces: v1alpha1.TargetNamespaceConfig{
					TargetNamespaces: []string{targetNSName},
					TargetNamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"x": "y"},
					},
				},
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoKubernetesAuthRole{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoKubernetesAuthRole{},
			types.NamespacedName{Namespace: OperatorNS, Name: roleBadCR},
			"Invalid", "")
	})
})
