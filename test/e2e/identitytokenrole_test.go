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

var _ = Describe("OpenBaoIdentityTokenRole CR → OpenBao", Ordered, func() {
	const (
		roleName  = "e2e-itr"
		roleBadCR = "e2e-itr-invalid"
		oidcKey   = "e2e-oidc-key"
		baoRole   = "e2e-itr-role"
	)

	var (
		k8s     client.Client
		bao     baoclient.Client
		httpBao *utils.BaoClient
		nn      types.NamespacedName
	)

	BeforeAll(func(ctx SpecContext) {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		httpBao = utils.NewBaoClientFromEnv()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: roleName}

		// Prereq: an OIDC signing key. The operator does not manage
		// these — they're administrator-provisioned. Write one
		// directly over HTTP so the spec can reference it.
		Expect(httpBao.WriteIdentityOIDCKey(ctx, oidcKey)).To(Succeed())
	})

	AfterAll(func(ctx SpecContext) {
		// Tolerate "already deleted" explicitly so a typo in oidcKey doesn't
		// silently turn a no-op cleanup into a passing test.
		if err := httpBao.DeleteIdentityOIDCKey(ctx, oidcKey); err != nil &&
			!errors.Is(err, utils.ErrIdentityOIDCKeyNotFound) {
			Fail(err.Error())
		}
	})

	It("creates an IdentityTokenRole CR and sees the role in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoIdentityTokenRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		}, nn)
		_ = bao.DeleteIdentityTokenRole(ctx, baoRole)

		cr := &v1alpha1.OpenBaoIdentityTokenRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
			Spec: v1alpha1.OpenBaoIdentityTokenRoleSpec{
				Name:     baoRole,
				Key:      oidcKey,
				ClientID: "e2e-client",
				TTL:      "1h",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			role, err := bao.ReadIdentityTokenRole(ctx, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.Key).To(Equal(oidcKey))
			g.Expect(role.ClientID).To(Equal("e2e-client"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoIdentityTokenRole{}, nn)
	})

	It("updates clientId when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoIdentityTokenRole{},
			func(cur *v1alpha1.OpenBaoIdentityTokenRole) {
				cur.Spec.ClientID = "e2e-client-2"
			})

		Eventually(func(g Gomega) {
			role, err := bao.ReadIdentityTokenRole(ctx, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.ClientID).To(Equal("e2e-client-2"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the role when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoIdentityTokenRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoIdentityTokenRole{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.ReadIdentityTokenRole(ctx, baoRole)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects an empty key", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoIdentityTokenRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			Spec: v1alpha1.OpenBaoIdentityTokenRoleSpec{
				Name: "e2e-itr-bad",
				Key:  "",
			},
		}
		err := k8s.Create(ctx, bad)
		Expect(err).To(HaveOccurred(), "CRD requires key MinLength=1")
	})
})
