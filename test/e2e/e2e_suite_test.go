/*
Copyright 2025 Stakater.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	crzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"

	_ "embed"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	_ "github.com/stakater-ab/mto-extension-openbao/test/utils"
)

//go:embed testdata/openbaoextension.yaml
var obxYAML []byte

// Exposed so other tests can use the actual name/ns applied here.
var (
	OBXName string
	OBXNS   string
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting mto-extension-openbao suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	// Enable controller-runtime logs in test output
	ctrl.SetLogger(crzap.New(crzap.UseDevMode(true)))

	if _, err := fmt.Fprintln(GinkgoWriter, "[DEBUG] BeforeSuite: applying OpenBaoExtension from testdata/openbaoextension.yaml"); err != nil {
		Expect(err).NotTo(HaveOccurred())
	}
	// Build k8s client with our API scheme
	scheme := runtime.NewScheme()
	Expect(extv1alpha1.AddToScheme(scheme)).To(Succeed())

	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred())

	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	// Namespace from env (must match your controller’s ns)
	ns := os.Getenv("OPERATOR_NS")
	Expect(ns).NotTo(BeEmpty(), "set OPERATOR_NS in make test-e2e")

	// Load CR from embedded YAML
	var obx extv1alpha1.OpenBaoExtension
	Expect(yaml.Unmarshal(obxYAML, &obx)).To(Succeed())

	url := os.Getenv("OPENBAO_URL")
	if url == "" {
		svc := getenv("OPENBAO_SVC", "openbao")
		baoNS := getenv("OPENBAO_NS", ns)
		proto := getenv("OPENBAO_SCHEME", "http")
		port := getenv("OPENBAO_PORT", "8200")
		url = fmt.Sprintf("%s://%s.%s.svc:%s", proto, svc, baoNS, port)
		if _, err := fmt.Fprintf(GinkgoWriter, "[DEBUG] Computed Bao URL from env: %s (svc=%s ns=%s scheme=%s port=%s)\n",
			url, svc, baoNS, proto, port); err != nil {
			Expect(err).NotTo(HaveOccurred())
		}
	}
	obx.Spec.Server.URL = url

	// override token Secret name/key to the one that actually exists
	secName := getenv("OPENBAO_TOKEN_SECRET", "mto-openbao-token")
	secKey := getenv("OPENBAO_TOKEN_KEY", "token")
	obx.Spec.Server.TokenSecretRef.Name = secName
	obx.Spec.Server.TokenSecretRef.Key = secKey

	if _, err := fmt.Fprintf(GinkgoWriter, "[DEBUG] Using token secret: %s/%s (key=%s)\n",
		ns, secName, secKey); err != nil {
		Expect(err).NotTo(HaveOccurred())
	}

	// Force namespace; keep name from file if present, else default
	if obx.Name == "" {
		obx.Name = "obx"
	}
	obx.Namespace = ns
	OBXName, OBXNS = obx.Name, obx.Namespace

	if _, err := fmt.Fprintf(GinkgoWriter,
		"[DEBUG] BeforeSuite: ns=%s name=%s url=%s tokenSecret=%s/%s\n",
		OBXNS, OBXName, obx.Spec.Server.URL,
		obx.Spec.Server.TokenSecretRef.Name, obx.Spec.Server.TokenSecretRef.Key,
	); err != nil {
		Expect(err).NotTo(HaveOccurred())
	}

	// Create or patch CR (retry on conflicts caused by controller status updates)
	ctx := context.Background()
	if err := k8s.Create(ctx, &obx); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if _, err := fmt.Fprintln(GinkgoWriter, "[DEBUG] BeforeSuite: CR exists; patching spec with retry"); err != nil {
				Expect(err).NotTo(HaveOccurred())
			}
			key := types.NamespacedName{Name: OBXName, Namespace: OBXNS}
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var cur extv1alpha1.OpenBaoExtension
				if err := k8s.Get(ctx, key, &cur); err != nil {
					return err
				}
				// Only change spec; avoid touching status/metadata.
				orig := cur.DeepCopy()
				cur.Spec = obx.Spec
				return k8s.Patch(ctx, &cur, client.MergeFrom(orig))
			})
			Expect(err).NotTo(HaveOccurred(), "conflict updating OpenBaoExtension spec")
			if _, err := fmt.Fprintln(GinkgoWriter, "[DEBUG] BeforeSuite: spec patched"); err != nil {
				Expect(err).NotTo(HaveOccurred())
			}
		} else {
			Fail(fmt.Sprintf("BeforeSuite create OpenBaoExtension failed: %v", err))
		}
	} else {
		fmt.Fprintln(GinkgoWriter, "[DEBUG] BeforeSuite: OpenBaoExtension created")
	}

	// Wait for AuthConfigured=True
	Eventually(func(g Gomega) bool {
		var got extv1alpha1.OpenBaoExtension
		err := k8s.Get(context.Background(),
			types.NamespacedName{Name: OBXName, Namespace: OBXNS}, &got)
		if err != nil {
			fmt.Fprintf(GinkgoWriter, "[DEBUG] BeforeSuite get error: %v\n", err)
			g.Expect(err).NotTo(HaveOccurred())
			return false
		}
		fmt.Fprintf(GinkgoWriter, "[DEBUG] BeforeSuite conditions=%v\n", got.Status.Conditions)

		// pass as soon as AuthConfigured=True is observed
		for _, c := range got.Status.Conditions {
			if c.Type == "AuthConfigured" && c.Status == metav1.ConditionTrue {
				return true
			}
		}
		return false
	}, 2*time.Minute, 2*time.Second).Should(BeTrue(),
		"AuthConfigured did not become True; check OPENBAO_* env and token secret")
})

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
