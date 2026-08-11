package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/test/utils"
)

// generateSelfSignedCAPEM returns a PEM-encoded self-signed CA. Bao only
// needs the cert to parse — it does not validate chain or trust.
func generateSelfSignedCAPEM() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "e2e cert-auth CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var _ = Describe("OpenBaoCertAuthEngineRole CR → OpenBao", Ordered, func() {
	const (
		amName     = "e2e-certrole-mount"
		secretName = "e2e-cert-ca-bundle"
		roleName   = "e2e-cert-role"
		roleBadCR  = "e2e-cert-role-invalid"
		mountPath  = "e2e-cert-role-auth"
		baoRole    = "e2e-cert-role"
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

		amTeardown = ensureAuthMethod(ctx, k8s, bao, amName, mountPath, v1alpha1.AuthMethodTypeCert)

		// CA bundle Secret.
		_ = k8s.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: secretName},
		})
		Expect(k8s.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: secretName},
			Data: map[string][]byte{
				"ca.crt": generateSelfSignedCAPEM(),
			},
		})).To(Succeed())
	})

	AfterAll(func(ctx SpecContext) {
		_ = k8s.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: secretName},
		})
		amTeardown(ctx)
	})

	It("creates a CertAuthRole CR and sees the cert entry in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoCertAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		}, nn)

		cr := &v1alpha1.OpenBaoCertAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
			Spec: v1alpha1.OpenBaoCertAuthEngineRoleSpec{
				Path: mountPath,
				Name: baoRole,
				CertificateRef: &v1alpha1.CertSecretRef{
					Name: secretName,
					Key:  "ca.crt",
				},
				DisplayName:        "e2e cert role",
				AllowedCommonNames: []string{"e2e-client"},
				TokenPolicies:      []string{"default"},
				TokenTTL:           "1h",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			role, err := bao.ReadCertAuthRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.DisplayName).To(Equal("e2e cert role"))
			g.Expect(role.AllowedCommonNames).To(ContainElement("e2e-client"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoCertAuthEngineRole{}, nn)
	})

	It("updates displayName when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoCertAuthEngineRole{},
			func(cur *v1alpha1.OpenBaoCertAuthEngineRole) {
				cur.Spec.DisplayName = "e2e cert role v2"
			})

		Eventually(func(g Gomega) {
			role, err := bao.ReadCertAuthRole(ctx, mountPath, baoRole)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.DisplayName).To(Equal("e2e cert role v2"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("deletes the cert entry when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoCertAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoCertAuthEngineRole{}, nn)

		Eventually(func(g Gomega) {
			_, err := bao.ReadCertAuthRole(ctx, mountPath, baoRole)
			g.Expect(errors.Is(err, baoclient.ErrNotFound)).To(BeTrue(),
				"expected ErrNotFound after CR delete, got %v", err)
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("rejects a role missing certificateRef", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoCertAuthEngineRole{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: roleBadCR},
			Spec: v1alpha1.OpenBaoCertAuthEngineRoleSpec{
				Path: mountPath,
				Name: "e2e-cert-role-bad",
			},
		}
		err := k8s.Create(ctx, bad)
		Expect(err).To(HaveOccurred(), "CRD requires certificateRef")
	})
})
