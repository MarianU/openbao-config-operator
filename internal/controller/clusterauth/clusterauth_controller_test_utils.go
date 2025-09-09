package clusterauth

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	obxv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
)

func ptr[T any](v T) *T { return &v }

func MinimalOpenBaoIntegration(ns, name, url, secretName, secretKey string) *obxv1alpha1.OpenBaoIntegration {
	return &obxv1alpha1.OpenBaoIntegration{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Spec: obxv1alpha1.OpenBaoIntegrationSpec{
			Server: obxv1alpha1.ServerSpec{
				URL: url,
				TokenSecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  secretKey,
				},
			},

			// keep both managers in ensure (your reconciler can start by only observing)
			AuthManagement: obxv1alpha1.AuthManagementSpec{
				Kubernetes: obxv1alpha1.AuthManageEnsure,
				OIDC:       obxv1alpha1.AuthManageEnsure,
			},

			// disable SSO for minimal path
			SSO: obxv1alpha1.SSOSpec{
				Mode: obxv1alpha1.SSOModeDisabled,
			},

			// required tenancy + defaults
			Tenancy: obxv1alpha1.TenancySpec{
				Mode: obxv1alpha1.TenancyPath,
				Defaults: obxv1alpha1.TenancyDefaults{
					Env: "prod",
				},
			},

			// at least one template entry required
			Layout: obxv1alpha1.LayoutSpec{
				Templates: map[string]string{
					"kv": `secret/tenants/{{ .tenant }}/{{ .env }}/{{ .namespace }}/{{ .app }}/{{ .name }}`,
				},
			},

			// RBAC token config expects pointers to metav1.Duration and *bool
			RBAC: obxv1alpha1.RBACSpec{
				RoleScope: obxv1alpha1.RoleScopeNamespace,
				Token: obxv1alpha1.RBACTokenSpec{
					TTL:       &metav1.Duration{Duration: time.Hour},
					MaxTTL:    &metav1.Duration{Duration: 4 * time.Hour},
					Renewable: ptr(false),
				},
			},

			// explicit tenant role mapping (defaults would also work, but explicit is clearer in tests)
			TenantRoleMapping: obxv1alpha1.TenantRoleMapping{
				Owner:  obxv1alpha1.PolicyAdmin,
				Editor: obxv1alpha1.PolicyEditor,
				Viewer: obxv1alpha1.PolicyViewer,
			},

			// engines must have at least one entry
			Engines: []obxv1alpha1.EngineSpec{
				{
					Name:      "kv",
					Type:      obxv1alpha1.EngineKVv2,
					LayoutRef: "kv",
					Enabled:   true,
					Strategy: obxv1alpha1.EngineStrategy{
						Scope: obxv1alpha1.StrategyCluster,
						Mount: obxv1alpha1.EngineStrategyMount{
							Path:   "/secret/tenants",
							Manage: obxv1alpha1.MountAdopt,
						},
					},
					Policies: obxv1alpha1.EnginePolicies{
						Presets: []obxv1alpha1.PolicyRole{
							obxv1alpha1.PolicyAdmin,
							obxv1alpha1.PolicyEditor,
							obxv1alpha1.PolicyViewer,
						},
					},
					Projection: obxv1alpha1.EngineProjection{
						Mode: obxv1alpha1.ProjectionNone,
					},
				},
			},

			Scaffolding: obxv1alpha1.ScaffoldingSpec{
				Mode: obxv1alpha1.ScaffoldOnAnnotation,
				Annotations: obxv1alpha1.ScaffoldingAnnotations{
					Enable: "mto.secrets/enable",
					Keys:   "mto.secrets/keys",
					Env:    "mto.secrets/env",
				},
			},

			Safety: obxv1alpha1.SafetySpec{
				AllowDeletes: false,
			},
		},
	}
}
