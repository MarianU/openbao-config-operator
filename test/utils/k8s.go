package utils

import (
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	extv1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
)

func GetK8sClient() client.Client {
	cfg := config.GetConfigOrDie()

	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed()) // core types
	Expect(extv1alpha1.AddToScheme(scheme)).To(Succeed())    // OpenBao* primitives

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	return c
}
