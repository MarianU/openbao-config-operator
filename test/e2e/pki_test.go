package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	"github.com/stakater-ab/mto-extension-openbao/test/utils"
)

// PKI e2e exercises the two intermediate-CA signing models against a live
// OpenBao. Mode 2 (internalSign) is fully automated; Mode 3 (externalSignSecret)
// simulates an offline signer by reading the operator-exported CSR Secret,
// signing it with the Mode-2 root, and placing the signed cert back.
var _ = Describe("OpenBaoPKISecretEngineConfig CR → OpenBao", Ordered, func() {
	const (
		rootMount = "e2e-pki-root"
		intMount  = "e2e-pki-int"
		extMount  = "e2e-pki-ext"

		rootCfg = "e2e-pki-root"
		intCfg  = "e2e-pki-int"
		extCfg  = "e2e-pki-ext"

		signSecretName = "e2e-pki-signed-ca"
	)

	var k8s client.Client
	var bao *utils.BaoClient

	BeforeAll(func() {
		k8s = utils.GetK8sClient()
		bao = utils.NewBaoClientFromEnv()
	})

	ensureEngine := func(ctx SpecContext, name, mount string) {
		eng := &v1alpha1.OpenBaoSecretEngine{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: OBXNS},
			Spec: v1alpha1.OpenBaoSecretEngineSpec{
				Path: mount,
				PKI:  &v1alpha1.PKISpec{},
			},
		}
		err := k8s.Create(ctx, eng)
		if err != nil {
			// Tolerate AlreadyExists from a prior run.
			Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		}
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoSecretEngine{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: OBXNS},
			})
		})
	}

	It("Mode 2 (internalSign): root signs an intermediate in-bao", func(ctx SpecContext) {
		By("enabling the root + intermediate PKI mounts")
		ensureEngine(ctx, rootCfg, rootMount)
		ensureEngine(ctx, intCfg, intMount)

		By("creating the root CA config")
		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Name: rootCfg, Namespace: OBXNS},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:       rootMount,
				Type:       v1alpha1.PKITypeRoot,
				CommonName: "E2E Root CA",
				TTL:        metav1.Duration{Duration: 87600 * time.Hour},
			},
		})).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
				ObjectMeta: metav1.ObjectMeta{Name: rootCfg, Namespace: OBXNS},
			})
		})

		By("observing the root CA in bao and Ready=True")
		Eventually(func(g Gomega) {
			cert, err := bao.GetPKICACert(ctx, rootMount)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cert).To(ContainSubstring("BEGIN CERTIFICATE"))
		}).WithTimeout(90 * time.Second).WithPolling(3 * time.Second).Should(Succeed())
		expectReady(ctx, k8s, rootCfg, metav1.ConditionTrue, "Reconciled")

		By("creating the intermediate config that internalSigns with the root mount")
		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Name: intCfg, Namespace: OBXNS},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:                intMount,
				Type:                v1alpha1.PKITypeIntermediate,
				CommonName:          "E2E Intermediate CA",
				TTL:                 metav1.Duration{Duration: 43800 * time.Hour},
				InternalSign:        &v1alpha1.PKIInternalSign{Name: rootMount},
				PermittedDnsDomains: []string{"svc.cluster.local"},
			},
		})).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
				ObjectMeta: metav1.ObjectMeta{Name: intCfg, Namespace: OBXNS},
			})
		})

		By("observing the signed intermediate CA in bao and Ready=True")
		Eventually(func(g Gomega) {
			cert, err := bao.GetPKICACert(ctx, intMount)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cert).To(ContainSubstring("BEGIN CERTIFICATE"))
		}).WithTimeout(120 * time.Second).WithPolling(3 * time.Second).Should(Succeed())
		expectReady(ctx, k8s, intCfg, metav1.ConditionTrue, "Reconciled")

		By("confirming the intermediate status booleans are stamped")
		var got v1alpha1.OpenBaoPKISecretEngineConfig
		Expect(k8s.Get(ctx, types.NamespacedName{Namespace: OBXNS, Name: intCfg}, &got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(v1alpha1.PhaseActive))
		Expect(got.Status.Signed).To(BeTrue())
		Expect(got.Status.CASerialNumber).NotTo(BeEmpty())
	})

	It("Mode 3 (externalSignSecret): waits for an offline-signed cert", func(ctx SpecContext) {
		By("enabling the external PKI mount")
		ensureEngine(ctx, extCfg, extMount)

		By("creating the external-sign intermediate config")
		Expect(k8s.Create(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
			ObjectMeta: metav1.ObjectMeta{Name: extCfg, Namespace: OBXNS},
			Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
				Path:               extMount,
				Type:               v1alpha1.PKITypeIntermediate,
				CommonName:         "E2E External Intermediate CA",
				TTL:                metav1.Duration{Duration: 43800 * time.Hour},
				ExternalSignSecret: &corev1.LocalObjectReference{Name: signSecretName},
			},
		})).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoPKISecretEngineConfig{
				ObjectMeta: metav1.ObjectMeta{Name: extCfg, Namespace: OBXNS},
			})
			_ = k8s.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: signSecretName, Namespace: OBXNS},
			})
		})

		By("observing Ready=False reason=AwaitingExternalSignature and the exported CSR Secret")
		expectReady(ctx, k8s, extCfg, metav1.ConditionFalse, "AwaitingExternalSignature")
		var csrSecret corev1.Secret
		csrKey := types.NamespacedName{Namespace: OBXNS, Name: extCfg + "-intermediate-csr"}
		Eventually(func(g Gomega) {
			g.Expect(k8s.Get(ctx, csrKey, &csrSecret)).To(Succeed())
			g.Expect(csrSecret.Data["csr"]).NotTo(BeEmpty())
		}).WithTimeout(90 * time.Second).WithPolling(3 * time.Second).Should(Succeed())

		By("simulating the offline signer: sign the CSR with the Mode-2 root")
		signed, err := bao.SignIntermediate(ctx, rootMount, string(csrSecret.Data["csr"]))
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(ContainSubstring("BEGIN CERTIFICATE"))

		By("placing the signed cert in the externalSignSecret")
		Expect(k8s.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: signSecretName, Namespace: OBXNS},
			Data:       map[string][]byte{"tls.crt": []byte(signed)},
		})).To(Succeed())

		By("observing the activated intermediate CA in bao and Ready=True")
		Eventually(func(g Gomega) {
			cert, err := bao.GetPKICACert(ctx, extMount)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cert).To(ContainSubstring("BEGIN CERTIFICATE"))
		}).WithTimeout(120 * time.Second).WithPolling(3 * time.Second).Should(Succeed())
		expectReady(ctx, k8s, extCfg, metav1.ConditionTrue, "Reconciled")
	})
})

// expectReady polls the CR until its Ready condition matches status+reason.
func expectReady(ctx SpecContext, k8s client.Client, name string, status metav1.ConditionStatus, reason string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		var got v1alpha1.OpenBaoPKISecretEngineConfig
		g.Expect(k8s.Get(ctx, types.NamespacedName{Namespace: OBXNS, Name: name}, &got)).To(Succeed())
		cond := findCond(got.Status.Conditions, "Ready")
		g.Expect(cond).NotTo(BeNil(), "Ready condition should be set")
		g.Expect(cond.Status).To(Equal(status))
		g.Expect(cond.Reason).To(Equal(reason))
	}).WithTimeout(90 * time.Second).WithPolling(3 * time.Second).Should(Succeed())
}
