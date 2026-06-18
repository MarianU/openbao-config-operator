package e2e

import (
	"context"
	"strings"
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

var _ = Describe("OpenBaoPKISecretEngineConfig CR → OpenBao", Ordered, func() {
	const (
		seName    = "e2e-pki-engine-cfg"
		cfgName   = "e2e-pki-config"
		cfgBadCR  = "e2e-pki-config-invalid"
		mountPath = "e2e-pki-cfg"
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
		nn = types.NamespacedName{Namespace: OperatorNS, Name: cfgName}

		seTeardown = ensureSecretEngine(ctx, k8s, bao, seName, mountPath,
			v1alpha1.OpenBaoSecretEngineSpec{PKI: &v1alpha1.PKISpec{}})
	})

	AfterAll(func(ctx SpecContext) { seTeardown(ctx) })

	It("creates a PKI config CR and sees the CA in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		}, nn)

		cr := &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:       mountPath,
				PKIType:    "root",
				CommonName: "e2e Root CA",
				TTL:        "8760h",
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			ca, err := bao.ReadPKICA(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(ca.Certificate)).To(HavePrefix("-----BEGIN CERTIFICATE-----"))
			// SerialNumber is not asserted: bao's /cert/ca returns it on some
			// versions but not on OpenBao 2.x dev mode.
		}).WithTimeout(90 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{}, nn)
	})

	It("updates URLs when spec.urls changes", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoPKISecretEngineConfig{},
			func(cur *v1alpha1.OpenBaoPKISecretEngineConfig) {
				cur.Spec.URLs = &v1alpha1.PKIURLs{
					IssuingCertificates:   []string{"https://e2e.example.com/v1/pki/ca"},
					CRLDistributionPoints: []string{"https://e2e.example.com/v1/pki/crl"},
				}
			})

		Eventually(func(g Gomega) {
			urls, err := bao.ReadPKIURLs(ctx, mountPath)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(urls.IssuingCertificates).To(ContainElement("https://e2e.example.com/v1/pki/ca"))
			g.Expect(urls.CRLDistributionPoints).To(ContainElement("https://e2e.example.com/v1/pki/crl"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("removes the CR on delete without touching the CA (IsDeletable=false)", func(ctx SpecContext) {
		// IsDeletable=false means CR delete only releases the finalizer;
		// the bao-side CA persists (re-creating a root CA would destroy
		// the private key). Assert the CR is gone but the CA still exists.
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{}, nn)

		ca, err := bao.ReadPKICA(ctx, mountPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.Certificate).NotTo(BeEmpty())
	})

	It("rejects an empty commonName", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: cfgBadCR},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:       mountPath,
				PKIType:    "root",
				CommonName: "",
			},
		}
		err := k8s.Create(ctx, bad)
		Expect(err).To(HaveOccurred(), "CRD requires commonName MinLength=1")
		Expect(err.Error()).To(Or(
			ContainSubstring("commonName"),
			ContainSubstring("MinLength"),
			ContainSubstring("should be at least"),
		))
	})
})
