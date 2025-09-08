package utils

import (
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	mto "github.com/stakater-ab/tenant-operator/api/v1beta3"
)

func GetK8sClient() client.Client {
	cfg := config.GetConfigOrDie()

	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed()) // core types
	Expect(mto.AddToScheme(scheme)).To(Succeed())            // Tenant v1beta3

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	return c
}
