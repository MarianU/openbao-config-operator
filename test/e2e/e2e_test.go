package e2e

import (
	. "github.com/onsi/ginkgo/v2"
)

// This file holds a placeholder E2E spec so the test package compiles
// even if no real tests are defined yet.
var _ = Describe("E2E (placeholder)", func() {
	It("does nothing", func() {
		// no-op
	})
})

//package e2e
//
//import (
//	"time"
//
//	. "github.com/onsi/ginkgo/v2"
//	. "github.com/onsi/gomega"
//
//	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
//	"sigs.k8s.io/controller-runtime/pkg/client"
//
//	mtocommon "github.com/stakater-ab/tenant-operator/api/common"
//	mto "github.com/stakater-ab/tenant-operator/api/v1beta3"
//
//	"github.com/stakater-ab/mto-extension-openbao/test/utils"
//)
//
//var _ = Describe("Tenant integration with OpenBao", Ordered, func() {
//	var k8sClient client.Client
//	var bao *utils.BaoClient
//
//	BeforeAll(func() {
//		k8sClient = utils.GetK8sClient()
//		bao = utils.NewBaoClientFromEnv()
//	})
//
//	It("should create mounts, policies, and roles per tenant namespace", func(ctx SpecContext) {
//		tenant := &mto.Tenant{
//			ObjectMeta: metav1.ObjectMeta{
//				Name: "mytenant",
//			},
//			Spec: mto.TenantSpec{
//				AccessControl: mto.AccessControl{
//					Owners: mtocommon.Members{Users: []string{"kubeadmin"}},
//				},
//				Namespaces: mto.NamespacesSpec{
//					WithTenantPrefix: []string{"namespace1", "namespace2"},
//				},
//			},
//		}
//
//		By("creating the Tenant")
//		Expect(k8sClient.Create(ctx, tenant)).To(Succeed())
//		DeferCleanup(func() {
//			_ = k8sClient.Delete(ctx, tenant)
//		})
//
//		By("verifying KV mounts exist")
//		Eventually(func(g Gomega) {
//			mounts, err := bao.ListMounts(ctx)
//			g.Expect(err).NotTo(HaveOccurred())
//			g.Expect(mounts.HasKVv2("secret/tenants/mytenant/prod/mytenant-namespace1/")).To(BeTrue())
//			g.Expect(mounts.HasKVv2("secret/tenants/mytenant/prod/mytenant-namespace2/")).To(BeTrue())
//		}).WithTimeout(90 * time.Second).WithPolling(5 * time.Second).Should(Succeed())
//
//		By("verifying policies exist")
//		Eventually(func(g Gomega) {
//			// naming rule: <tenant>-<namespace>-<role>
//			pol, err := bao.GetPolicy(ctx, "mytenant-mytenant-namespace1-editor")
//			g.Expect(err).NotTo(HaveOccurred())
//			g.Expect(pol).To(ContainSubstring("tenants/mytenant/prod/mytenant-namespace1"))
//		}).WithTimeout(60 * time.Second).Should(Succeed())
//
//		By("verifying k8s auth role exists")
//		Eventually(func(g Gomega) {
//			// naming rule: <tenant>-<namespace>
//			role, err := bao.GetK8sRole(ctx, "mytenant-mytenant-namespace1")
//			g.Expect(err).NotTo(HaveOccurred())
//			g.Expect(role.Policies).To(ContainElement("mytenant-mytenant-namespace1-editor"))
//			g.Expect(role.BoundNamespaces).To(ContainElement("mytenant-namespace1"))
//		}).WithTimeout(60 * time.Second).Should(Succeed())
//	})
//})
