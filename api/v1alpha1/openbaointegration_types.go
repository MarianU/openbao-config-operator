package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------- Enums ----------

type AuthManageMode string

const (
	AuthManageOff    AuthManageMode = "off"
	AuthManageEnsure AuthManageMode = "ensure"
)

// +kubebuilder:validation:Enum=cluster;secret;inline;disabled
type SSOMode string

const (
	SSOModeCluster  SSOMode = "cluster"
	SSOModeSecret   SSOMode = "secret"
	SSOModeInline   SSOMode = "inline"
	SSOModeDisabled SSOMode = "disabled"
)

// +kubebuilder:validation:Enum=highest;lowest;deny
type TieBreakStrategy string

const (
	TieBreakHighest TieBreakStrategy = "highest"
	TieBreakLowest  TieBreakStrategy = "lowest"
	TieBreakDeny    TieBreakStrategy = "deny"
)

// +kubebuilder:validation:Enum=path;namespace
type TenancyMode string

const (
	TenancyPath      TenancyMode = "path"
	TenancyNamespace TenancyMode = "namespace"
)

// +kubebuilder:validation:Enum=namespace;app
type RoleScope string

const (
	RoleScopeNamespace RoleScope = "namespace"
	RoleScopeApp       RoleScope = "app"
)

// +kubebuilder:validation:Enum=admin;editor;viewer;none
type PolicyRole string

const (
	PolicyAdmin  PolicyRole = "admin"
	PolicyEditor PolicyRole = "editor"
	PolicyViewer PolicyRole = "viewer"
	PolicyNone   PolicyRole = "none"
)

// +kubebuilder:validation:Enum=owner;editor;viewer
type TenantRole string

const (
	TenantOwner  TenantRole = "owner"
	TenantEditor TenantRole = "editor"
	TenantViewer TenantRole = "viewer"
)

// +kubebuilder:validation:Enum=owner;editor;viewer;deny
type TenantRoleOrDeny string

const (
	TenantFallbackOwner  TenantRoleOrDeny = "owner"
	TenantFallbackEditor TenantRoleOrDeny = "editor"
	TenantFallbackViewer TenantRoleOrDeny = "viewer"
	TenantFallbackDeny   TenantRoleOrDeny = "deny"
)

// +kubebuilder:validation:Enum=external-secrets;csi;none
type ProjectionMode string

const (
	ProjectionExternalSecrets ProjectionMode = "external-secrets"
	ProjectionCSI             ProjectionMode = "csi"
	ProjectionNone            ProjectionMode = "none"
)

// +kubebuilder:validation:Enum=namespace;cluster
type SecretStoreScope string

const (
	SecretStoreNamespace SecretStoreScope = "namespace"
	SecretStoreCluster   SecretStoreScope = "cluster"
)

// +kubebuilder:validation:Enum=kv-v2
type EngineType string

const (
	EngineKVv2 EngineType = "kv-v2"
)

// +kubebuilder:validation:Enum=cluster;tenant
type StrategyScope string

const (
	StrategyCluster StrategyScope = "cluster"
	StrategyTenant  StrategyScope = "tenant"
)

// +kubebuilder:validation:Enum=off;adopt;ensure
type MountManage string

const (
	MountOff    MountManage = "off"
	MountAdopt  MountManage = "adopt"
	MountEnsure MountManage = "ensure"
)

// ---------- Spec ----------

type ServerSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=uri
	URL string `json:"url"`

	// Secret with a "token" key (or configured key) containing a Bao token
	// scoped to the operator's service account.
	// +kubebuilder:validation:Required
	TokenSecretRef corev1.SecretKeySelector `json:"tokenSecretRef"`
}

type AuthManagementSpec struct {
	// +kubebuilder:default:=ensure
	// +kubebuilder:validation:Enum=off;ensure
	Kubernetes AuthManageMode `json:"kubernetes"`

	// +kubebuilder:default:=ensure
	// +kubebuilder:validation:Enum=off;ensure
	OIDC AuthManageMode `json:"oidc"`
}

type SSOClusterRef struct {
	// Name of the cluster-wide SSO config resource your extension provides.
	// (Opaque to this CRD; your operator resolves it.)
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type RoleResolutionPattern struct {
	// +kubebuilder:validation:Enum=owner;editor;viewer
	Role TenantRole `json:"role"`

	// Template-aware group matcher, e.g., "tenant-{{ .tenant }}-owners".
	// +kubebuilder:validation:MinLength=1
	Match string `json:"match"`
}

type RoleResolutionSpec struct {
	// Claim to inspect (e.g., "groups").
	// +kubebuilder:validation:MinLength=1
	Claim string `json:"claim"`

	// +kubebuilder:validation:MinItems=1
	Patterns []RoleResolutionPattern `json:"patterns"`

	// +kubebuilder:default:=highest
	TieBreakStrategy TieBreakStrategy `json:"tieBreakStrategy"`

	// +kubebuilder:default:=deny
	Fallback TenantRoleOrDeny `json:"fallback"`
}

type SSOSpec struct {
	// +kubebuilder:default:=cluster
	// +kubebuilder:validation:Enum=cluster;secret;inline;disabled
	Mode SSOMode `json:"mode"`

	// Present when mode=cluster.
	// +optional
	ClusterRef *SSOClusterRef `json:"clusterRef,omitempty"`

	// Present when mode=secret. Secret data/keys are defined by your extension.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// Present when mode=inline. Opaque key/value bag to keep the CRD general.
	// +optional
	Inline map[string]string `json:"inline,omitempty"`

	// Required except when mode=disabled.
	// +optional
	RoleResolution *RoleResolutionSpec `json:"roleResolution,omitempty"`

	// Enforce mode-specific required fields.
	// cluster → clusterRef required; secret → secretRef required; inline → inline required; disabled → roleResolution must be absent.
	// +kubebuilder:validation:XValidation:rule="self.mode != 'cluster' || has(self.clusterRef)",message="clusterRef is required when mode=cluster"
	// +kubebuilder:validation:XValidation:rule="self.mode != 'secret' || has(self.secretRef)",message="secretRef is required when mode=secret"
	// +kubebuilder:validation:XValidation:rule="self.mode != 'inline' || has(self.inline)",message="inline is required when mode=inline"
	// +kubebuilder:validation:XValidation:rule="self.mode != 'disabled' || !has(self.roleResolution)",message="roleResolution must be omitted when mode=disabled"
}

type TenancyDefaults struct {
	// +kubebuilder:default:=prod
	// +kubebuilder:validation:MinLength=1
	Env string `json:"env"`
}

type TenancySpec struct {
	// +kubebuilder:default:=path
	// +kubebuilder:validation:Enum=path;namespace
	Mode TenancyMode `json:"mode"`

	Defaults TenancyDefaults `json:"defaults"`
}

type LayoutSpec struct {
	// Named templates. Example:
	//   kv: "secret/tenants/{{ .tenant }}/{{ .env }}/{{ .namespace }}/{{ .app }}/{{ .name }}"
	// +kubebuilder:validation:MinProperties=1
	Templates map[string]string `json:"templates"`
}

type RBACTokenSpec struct {
	// +kubebuilder:default:="1h"
	TTL *metav1.Duration `json:"ttl,omitempty"`

	// +kubebuilder:default:="4h"
	MaxTTL *metav1.Duration `json:"maxTTL,omitempty"`

	// +optional
	Renewable *bool `json:"renewable,omitempty"`
}

type RBACSpec struct {
	// +kubebuilder:default:=namespace
	// +kubebuilder:validation:Enum=namespace;app
	RoleScope RoleScope `json:"roleScope"`

	Token RBACTokenSpec `json:"token"`
}

type TenantRoleMapping struct {
	// +kubebuilder:default:=admin
	// +kubebuilder:validation:Enum=admin;editor;viewer;none
	Owner PolicyRole `json:"owner"`

	// +kubebuilder:default:=editor
	// +kubebuilder:validation:Enum=admin;editor;viewer;none
	Editor PolicyRole `json:"editor"`

	// +kubebuilder:default:=viewer
	// +kubebuilder:validation:Enum=admin;editor;viewer;none
	Viewer PolicyRole `json:"viewer"`
}

type EngineStrategyMount struct {
	// e.g., "secret" → /v1/secret (kv-v2)
	// +kubebuilder:validation:MinLength=1
	Path string `json:"path"`

	// +kubebuilder:default:=adopt
	// +kubebuilder:validation:Enum=off;adopt;ensure
	Manage MountManage `json:"manage"`
}

type EngineStrategy struct {
	// +kubebuilder:default:=cluster
	// +kubebuilder:validation:Enum=cluster;tenant
	Scope StrategyScope `json:"scope"`

	Mount EngineStrategyMount `json:"mount"`
}

type EnginePolicies struct {
	// List of Bao policy presets to materialize for this engine.
	// +kubebuilder:validation:MinItems=1
	Presets []PolicyRole `json:"presets"`
}

type ProjectionSecretStore struct {
	// +kubebuilder:default:=namespace
	// +kubebuilder:validation:Enum=namespace;cluster
	Scope SecretStoreScope `json:"scope"`

	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type EngineProjection struct {
	// +kubebuilder:default:=external-secrets
	// +kubebuilder:validation:Enum=external-secrets;csi;none
	Mode ProjectionMode `json:"mode"`

	// Required when mode=external-secrets; must be omitted otherwise.
	// +optional
	SecretStore *ProjectionSecretStore `json:"secretStore,omitempty"`

	// +kubebuilder:validation:XValidation:rule="self.mode != 'external-secrets' || has(self.secretStore)",message="secretStore is required when projection.mode=external-secrets"
	// +kubebuilder:validation:XValidation:rule="self.mode == 'external-secrets' || !has(self.secretStore)",message="secretStore must be omitted unless projection.mode=external-secrets"
}

type EngineSpec struct {
	// Logical name of this engine config, e.g., "kv".
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Enum=kv-v2
	Type EngineType `json:"type"`

	// Reference to a layout template key, e.g., "kv".
	// +kubebuilder:validation:MinLength=1
	LayoutRef string `json:"layoutRef"`

	// +kubebuilder:default:=true
	Enabled bool `json:"enabled"`

	Strategy   EngineStrategy   `json:"strategy"`
	Policies   EnginePolicies   `json:"policies"`
	Projection EngineProjection `json:"projection"`
}

type ScaffoldingAnnotations struct {
	// +kubebuilder:default:="mto.secrets/enable"
	Enable string `json:"enable"`

	// +kubebuilder:default:="mto.secrets/keys"
	Keys string `json:"keys"`

	// +kubebuilder:default:="mto.secrets/env"
	Env string `json:"env"`
}

// +kubebuilder:validation:Enum=none;on-annotation
type ScaffoldingMode string

const (
	ScaffoldNone         ScaffoldingMode = "none"
	ScaffoldOnAnnotation ScaffoldingMode = "on-annotation"
)

type ScaffoldingSpec struct {
	// +kubebuilder:default:=on-annotation
	// +kubebuilder:validation:Enum=none;on-annotation
	Mode ScaffoldingMode `json:"mode"`

	Annotations ScaffoldingAnnotations `json:"annotations"`
}

type SafetySpec struct {
	// In kv-v2, "delete" hides a version; "destroy" permanently deletes it.
	// +kubebuilder:default:=false
	AllowDeletes bool `json:"allowDeletes"`
}

// ---------- Top-level Spec & Status ----------

type OpenBaoIntegrationSpec struct {
	Server            ServerSpec         `json:"server"`
	AuthManagement    AuthManagementSpec `json:"authManagement"`
	SSO               SSOSpec            `json:"sso"`
	Tenancy           TenancySpec        `json:"tenancy"`
	Layout            LayoutSpec         `json:"layout"`
	RBAC              RBACSpec           `json:"rbac"`
	TenantRoleMapping TenantRoleMapping  `json:"tenantRoleMapping"`

	// +kubebuilder:validation:MinItems=1
	Engines []EngineSpec `json:"engines"`

	Scaffolding ScaffoldingSpec `json:"scaffolding"`
	Safety      SafetySpec      `json:"safety"`
}

type OpenBaoIntegrationStatus struct {
	// Standard conditions: Ready, AuthConfigured, EnginesSynced, etc.
	// Keep minimal; extend as implementation matures.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=obint;scope=Namespaced
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.tenancy.mode`,priority=0
// +kubebuilder:printcolumn:name="SSO",type=string,JSONPath=`.spec.sso.mode`,priority=0
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,priority=0
type OpenBaoIntegration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoIntegrationSpec   `json:"spec,omitempty"`
	Status OpenBaoIntegrationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type OpenBaoIntegrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoIntegration `json:"items"`
}
