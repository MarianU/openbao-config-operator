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

var _ = Describe("OpenBaoPKISecretEngineRole CR → OpenBao", Ordered, func() {
	const (
		seName    = "e2e-pki-engine-role"
		cfgName   = "e2e-pki-config-for-role"
		roleName  = "e2e-pki-role"
		roleBadCR = "e2e-pki-role-invalid"
		mountPath = "e2e-pki-role-mount"
		baoRole   = "e2e-role"
	)

	var (
		k8s        client.Client
		bao        baoclient.Client
		nn         types.NamespacedName
		seTeardown func(context.Context)
	)

	BeforeAll(func(ctx SpecContext) {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: roleName}

		seTeardown = ensureSecretEngine(ctx, k8s, bao, seName, mountPath,
			v1alpha1.OpenBaoSecretEngineSpec{PKI: &v1alpha1.PKISpec{}})

		// Inline prereq: a PKI config with a CA at the same mount. Used
		// here only — not worth its own helper.
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		}, types.NamespacedName{Namespace: OperatorNS, Name: cfgName})
		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:       mountPath,
				PKIType:    "root",
				CommonName: "e2e PKI Role CA",
				TTL:        "8760h",
			},
		})).To(Succeed())
		expectReady(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{},
			types.NamespacedName{Namespace: OperatorNS, Name: cfgName})
	})

	AfterAll(func(ctx SpecContext) {
		_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		})
		seTeardown(ctx)
	})

	It("creates a PKI role CR and sees the role in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		}, nn)

		cr := &v1alpha1.OpenBaoPKISecretEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
			Spec: v1alpha1.OpenBaoPKISecretEngineRoleSpec{
				Path:            mountPath,
				Name:            baoRole,
				AllowedDomains:  []string{"e2e.example.com"},
				AllowSubdomains: true,
				ServerFlag:      true,
				KeyType:         "rsa",
				KeyBits:         2048,
				TTL:             "1h",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			role, err := bao.ReadPKIRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.AllowedDomains).To(ContainElement("e2e.example.com"))
			g.Expect(role.AllowSubdomains).To(BeTrue())
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineRole{}, nn)
	})

	It("updates allowedDomains when spec changes", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoPKISecretEngineRole{},
			func(cur *v1alpha1.OpenBaoPKISecretEngineRole) {
				cur.Spec.AllowedDomains = []string{"e2e.example.com", "alt.example.com"}
			})

		Eventually(func(g Gomega) {
			role, err := bao.ReadPKIRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.AllowedDomains).To(ConsistOf("e2e.example.com", "alt.example.com"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the role when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineRole{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.ReadPKIRole(ctx, mountPath, baoRole)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects a role with no allow-* flags set", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoPKISecretEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			Spec: v1alpha1.OpenBaoPKISecretEngineRoleSpec{
				Path: mountPath,
				Name: "e2e-role-bad",
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineRole{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineRole{},
			types.NamespacedName{Namespace: OperatorNS, Name: roleBadCR},
			"Invalid", "allow")
	})
})
