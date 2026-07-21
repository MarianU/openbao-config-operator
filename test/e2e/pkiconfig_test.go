package e2e

import (
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/test/utils"
)

// PKI config e2e exercises root-CA generation, URL drift, and both
// intermediate-CA signing models against a live OpenBao. Mode 2
// (internalSign) signs the intermediate in-bao; Mode 3 (externalSignSecret)
// simulates an offline signer by reading the operator-exported CSR Secret,
// signing it with the Mode-2 root, and placing the signed cert back.
var _ = Describe("OpenBaoPKISecretEngineConfig CR → OpenBao", Ordered, func() {
	const (
		rootSE  = "e2e-pki-root-engine"
		rootCfg = "e2e-pki-root"
		rootMnt = "e2e-pki-root"

		intSE  = "e2e-pki-int-engine"
		intCfg = "e2e-pki-int"
		intMnt = "e2e-pki-int"

		extSE  = "e2e-pki-ext-engine"
		extCfg = "e2e-pki-ext"
		extMnt = "e2e-pki-ext"

		signSecretName = "e2e-pki-signed-ca"
		badCfg         = "e2e-pki-config-invalid"
	)

	var (
		k8s       client.Client
		bao       baoclient.Client
		rootKey   types.NamespacedName
		intKey    types.NamespacedName
		extKey    types.NamespacedName
		teardowns []func(context.Context)
	)

	BeforeAll(func(ctx SpecContext) {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		rootKey = types.NamespacedName{Namespace: OperatorNS, Name: rootCfg}
		intKey = types.NamespacedName{Namespace: OperatorNS, Name: intCfg}
		extKey = types.NamespacedName{Namespace: OperatorNS, Name: extCfg}

		// One PKI mount per config; the config CR populates the mount its
		// engine enabled. ensureSecretEngine waits for Ready=True.
		teardowns = append(teardowns,
			ensureSecretEngine(ctx, k8s, bao, rootSE, rootMnt,
				v1alpha1.OpenBaoSecretEngineSpec{PKI: &v1alpha1.PKISpec{}}),
			ensureSecretEngine(ctx, k8s, bao, intSE, intMnt,
				v1alpha1.OpenBaoSecretEngineSpec{PKI: &v1alpha1.PKISpec{}}),
			ensureSecretEngine(ctx, k8s, bao, extSE, extMnt,
				v1alpha1.OpenBaoSecretEngineSpec{PKI: &v1alpha1.PKISpec{}}),
		)
	})

	AfterAll(func(ctx SpecContext) {
		// Disabling the mounts (in reverse order) drops the CAs; the config
		// CRs are IsDeletable=false so they never touch bao on delete.
		for i := len(teardowns) - 1; i >= 0; i-- {
			teardowns[i](ctx)
		}
	})

	It("creates a root CA config and sees the CA in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: rootCfg},
		}, rootKey)

		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: rootCfg},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:       rootMnt,
				Type:       v1alpha1.PKITypeRoot,
				CommonName: "E2E Root CA",
				TTL:        metav1.Duration{Duration: 87600 * time.Hour},
			},
		})).To(Succeed())
		// Root cleanup is owned by the IsDeletable spec at the end.

		Eventually(func(g Gomega) {
			ca, err := bao.ReadPKICA(ctx, rootMnt)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(ca.Certificate)).To(HavePrefix("-----BEGIN CERTIFICATE-----"))
			// SerialNumber is not asserted: bao's /cert/ca returns it on some
			// versions but not on OpenBao 2.x dev mode.
		}).WithTimeout(90 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{}, rootKey)
	})

	It("updates the CA URL distribution points when the spec changes", func(ctx SpecContext) {
		patchSpec(ctx, k8s, rootKey, &v1alpha1.OpenBaoPKISecretEngineConfig{},
			func(cur *v1alpha1.OpenBaoPKISecretEngineConfig) {
				cur.Spec.IssuingCertificates = []string{"https://e2e.example.com/v1/pki/ca"}
				cur.Spec.CRLDistributionPoints = []string{"https://e2e.example.com/v1/pki/crl"}
			})

		Eventually(func(g Gomega) {
			urls, err := bao.ReadPKIURLs(ctx, rootMnt)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(urls.IssuingCertificates).To(ContainElement("https://e2e.example.com/v1/pki/ca"))
			g.Expect(urls.CRLDistributionPoints).To(ContainElement("https://e2e.example.com/v1/pki/crl"))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("signs an intermediate in-bao via internalSign (Mode 2)", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: intCfg},
		}, intKey)

		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: intCfg},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:                intMnt,
				Type:                v1alpha1.PKITypeIntermediate,
				CommonName:          "E2E Intermediate CA",
				TTL:                 metav1.Duration{Duration: 43800 * time.Hour},
				InternalSign:        &v1alpha1.PKIInternalSign{Name: rootMnt},
				PermittedDnsDomains: []string{"svc.cluster.local"},
			},
		})).To(Succeed())

		Eventually(func(g Gomega) {
			ca, err := bao.ReadPKICA(ctx, intMnt)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ca.Certificate).To(ContainSubstring("BEGIN CERTIFICATE"))
		}).WithTimeout(120 * time.Second).WithPolling(3 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{}, intKey)

		By("confirming the intermediate status is stamped")
		var got v1alpha1.OpenBaoPKISecretEngineConfig
		Expect(k8s.Get(ctx, intKey, &got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(v1alpha1.PhaseActive))
		Expect(got.Status.Signed).To(BeTrue())
		Expect(got.Status.CASerialNumber).NotTo(BeEmpty())
	})

	It("waits for an offline-signed cert via externalSignSecret (Mode 3)", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: extCfg},
		}, extKey)

		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: extCfg},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:               extMnt,
				Type:               v1alpha1.PKITypeIntermediate,
				CommonName:         "E2E External Intermediate CA",
				TTL:                metav1.Duration{Duration: 43800 * time.Hour},
				ExternalSignSecret: &corev1.LocalObjectReference{Name: signSecretName},
			},
		})).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: signSecretName},
			})
		})

		By("observing Ready=False reason=AwaitingExternalSignature and the exported CSR Secret")
		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{}, extKey,
			"AwaitingExternalSignature", "")

		var csrSecret corev1.Secret
		csrKey := types.NamespacedName{Namespace: OperatorNS, Name: extCfg + "-intermediate-csr"}
		Eventually(func(g Gomega) {
			g.Expect(k8s.Get(ctx, csrKey, &csrSecret)).To(Succeed())
			g.Expect(csrSecret.Data["csr"]).NotTo(BeEmpty())
		}).WithTimeout(90 * time.Second).WithPolling(3 * time.Second).Should(Succeed())

		By("simulating the offline signer: sign the CSR with the Mode-2 root")
		signed, err := bao.SignIntermediate(ctx, rootMnt, string(csrSecret.Data["csr"]),
			baoclient.PKISignIntermediateInput{TTL: "43800h", Format: "pem_bundle"})
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(ContainSubstring("BEGIN CERTIFICATE"))

		By("placing the signed cert in the externalSignSecret")
		Expect(k8s.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: signSecretName},
			Data:       map[string][]byte{"tls.crt": []byte(signed)},
		})).To(Succeed())

		By("observing the activated intermediate CA in bao and Ready=True")
		Eventually(func(g Gomega) {
			ca, err := bao.ReadPKICA(ctx, extMnt)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(ca.Certificate).To(ContainSubstring("BEGIN CERTIFICATE"))
		}).WithTimeout(120 * time.Second).WithPolling(3 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{}, extKey)
	})

	It("rejects an empty commonName at admission", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: badCfg},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:       rootMnt,
				Type:       v1alpha1.PKITypeRoot,
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

	It("removes the CR on delete without touching the CA (IsDeletable=false)", func(ctx SpecContext) {
		// IsDeletable=false means CR delete only releases the finalizer;
		// the bao-side CA persists (re-creating a root CA would destroy
		// the private key). Assert the CR is gone but the CA still exists.
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: rootCfg},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoPKISecretEngineConfig{}, rootKey)

		ca, err := bao.ReadPKICA(ctx, rootMnt)
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.Certificate).NotTo(BeEmpty())
	})
})
