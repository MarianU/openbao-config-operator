package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater-ab/mto-extension-openbao/test/utils"
	mtocommon "github.com/stakater-ab/tenant-operator/api/common"
	mto "github.com/stakater-ab/tenant-operator/api/v1beta3"
)

var _ = Describe("Tenant → OpenBao (namespace granularity)", Ordered, func() {
	var k8sClient client.Client
	var bao *utils.BaoClient

	BeforeAll(func() {
		k8sClient = utils.GetK8sClient()
		bao = utils.NewBaoClientFromEnv()
	})

	It("creates mounts, policies, and roles per tenant namespace", func(ctx SpecContext) {
		tenant := &mto.Tenant{
			ObjectMeta: metav1.ObjectMeta{
				Name: "mytenant",
			},
			Spec: mto.TenantSpec{
				AccessControl: mto.AccessControl{
					Owners: mtocommon.Members{Users: []string{"kubeadmin"}},
				},
				Namespaces: &mto.Namespaces{
					WithTenantPrefix: []mtocommon.Namespace{
						"namespace1",
						"namespace2",
					},
				},
			},
		}

		By("ensuring no leftover Tenant from previous runs")
		_ = k8sClient.Delete(ctx, &mto.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "mytenant"}})
		Eventually(func() bool {
			var t mto.Tenant
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "mytenant"}, &t) // cluster-scoped
			return k8serrors.IsNotFound(err)
		}).WithTimeout(30*time.Second).WithPolling(1*time.Second).Should(BeTrue(), "leftover Tenant/mytenant should be gone")

		By("creating the Tenant")
		Expect(k8sClient.Create(ctx, tenant)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, tenant) })

		By("verifying the base KV v2 mount exists at secret/")
		Eventually(func(g Gomega) {
			mounts, err := bao.ListMounts(ctx)
			g.Expect(err).NotTo(HaveOccurred())
			// The operator writes under subpaths of the single KV v2 engine at "secret/".
			g.Expect(mounts.HasKVv2("secret/")).To(BeTrue())
		}).WithTimeout(10 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		By("verifying policy exists for one namespace (naming: <tenant>-<namespace>-<role>)")
		Eventually(func(g Gomega) {
			pol, err := bao.GetPolicy(ctx, "mytenant-mytenant-namespace1-editor")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(pol).To(ContainSubstring("path \"secret/data/tenants/mytenant/prod/mytenant-namespace1/"))
			g.Expect(pol).To(ContainSubstring("path \"secret/metadata/tenants/mytenant/prod/mytenant-namespace1/"))
		}).WithTimeout(10 * time.Second).Should(Succeed())

		By("verifying k8s auth role exists for that namespace (naming: <tenant>-<namespace>)")
		Eventually(func(g Gomega) {
			role, err := bao.GetK8sRole(ctx, "mytenant-mytenant-namespace1")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(role.Policies).To(ContainElement("mytenant-mytenant-namespace1-editor"))
			// We assert it binds the Kubernetes namespace `mytenant-namespace1`
			g.Expect(role.BoundServiceAccountNamespaces).To(ContainElement("mytenant-namespace1"))
		}).WithTimeout(10 * time.Second).Should(Succeed())
	})
})
