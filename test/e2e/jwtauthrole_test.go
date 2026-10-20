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

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/test/utils"
)

var _ = Describe("OpenBaoJWTOIDCAuthEngineRole CR → OpenBao", Ordered, func() {
	const (
		amName    = "e2e-jwtrole-mount"
		roleName  = "e2e-jwt-role"
		roleBadCR = "e2e-jwt-role-invalid"
		mountPath = "e2e-jwt-role-auth"
		baoRole   = "e2e-jwt-role"
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

		amTeardown = ensureAuthMethod(ctx, k8s, bao, amName, mountPath, v1alpha1.AuthMethodTypeJWT)
	})

	AfterAll(func(ctx SpecContext) { amTeardown(ctx) })

	It("creates a JWTOIDC role CR and sees the role in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		}, nn)

		cr := &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
			Spec: v1alpha1.OpenBaoJWTOIDCAuthEngineRoleSpec{
				Path:           mountPath,
				Name:           baoRole,
				RoleType:       "jwt",
				UserClaim:      "sub",
				BoundAudiences: []string{"e2e-aud"},
				TokenPolicies:  []string{"default"},
				TokenTTL:       "1h",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			role, err := bao.ReadJWTOIDCRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.RoleType).To(Equal("jwt"))
			g.Expect(role.UserClaim).To(Equal("sub"))
			g.Expect(role.BoundAudiences).To(ContainElement("e2e-aud"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{}, nn)
	})

	It("updates boundAudiences when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{},
			func(cur *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) {
				cur.Spec.BoundAudiences = []string{"e2e-aud", "e2e-aud-2"}
			})

		Eventually(func(g Gomega) {
			role, err := bao.ReadJWTOIDCRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.BoundAudiences).To(ConsistOf("e2e-aud", "e2e-aud-2"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the role when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.ReadJWTOIDCRole(ctx, mountPath, baoRole)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects roleType=oidc with no allowedRedirectUris", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			Spec: v1alpha1.OpenBaoJWTOIDCAuthEngineRoleSpec{
				Path:      mountPath,
				Name:      "e2e-jwt-role-bad",
				RoleType:  "oidc",
				UserClaim: "sub",
				// allowedRedirectUris omitted on purpose.
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{},
			types.NamespacedName{Namespace: OperatorNS, Name: roleBadCR},
			"Invalid", "")
	})
})
