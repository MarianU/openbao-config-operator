// Package client is the wrapper (facade) layer over hashicorp/vault/api.
//
// Callers (ClusterAuth, Tenant, the VCO-origin primitive controllers) depend
// only on the Client interface below. This file wires each method to the
// corresponding vault/api call, so callers never have to know we use the
// SDK internally. The wrapper exists to (1) keep callers SDK-agnostic so
// the implementation is swappable, (2) translate SDK error shapes into the
// project-local *StatusError / ErrNotFound contract every controller
// already classifies on, and (3) centralize idempotency quirks like the
// "path is already in use" 400 from sys/auth. OpenBao is wire-compatible
// with Vault, so all of these calls work unchanged against an OpenBao
// server.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// All Get* methods report a missing object the same way: they return
// ErrNotFound (with the zero value for the data return). Callers classify
// with errors.Is(err, client.ErrNotFound). Other errors retain their
// structured form (*StatusError, network errors, etc.).
//
// Every method accepts variadic CallOptions; the current option set is just
// WithNamespace for scoping a call to an OpenBao namespace. Passing no opts
// targets the root namespace and matches pre-namespace-support behaviour.
type Client interface {
	CheckKVv2Mount(ctx context.Context, mount string, opts ...CallOption) (bool, error)
	CheckAuthMount(ctx context.Context, mount string, opts ...CallOption) (bool, error)
	EnableAuthMount(ctx context.Context, mount string, typ string, opts ...CallOption) error

	// Secret-engine mount lifecycle (sys/mounts/<path>). Used by the
	// OpenBaoSecretEngine controller to manage KV / Transit / PKI mounts.
	// EnableSecretEngine creates the mount; TuneSecretEngine updates
	// tunable fields (description, options) on an existing mount.
	// EnableSecretEngine is idempotent on "path already in use" so the
	// controller can call it unconditionally on the create path; the
	// update path uses TuneSecretEngine because bao's enable endpoint
	// does NOT update an existing mount, it returns 400.
	EnableSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error
	TuneSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error
	GetSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) (*SecretEngineMount, error)
	DisableSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) error

	// Auth-mount read + delete (sys/auth/<path>). EnableAuthMount above
	// owns the create path; these handle drift inspection and cleanup.
	GetAuthMount(ctx context.Context, mount string, opts ...CallOption) (*AuthMount, error)
	DisableAuthMount(ctx context.Context, mount string, opts ...CallOption) error

	// Auth-mount enable + tune (sys/auth/<path>). The historical
	// EnableAuthMount above is kept for ClusterAuth's narrow
	// "ensure-kubernetes-mount" use case (type-only; no description /
	// options / config). EnableAuthMethod and TuneAuthMethod take a
	// richer spec so the OpenBaoAuthMethod controller can manage
	// arbitrary auth mounts. The two methods diverge for the same
	// reason EnableSecretEngine / TuneSecretEngine diverge: bao's
	// enable endpoint creates only — re-enable returns 400 "already
	// in use" — so the update path must call tune.
	EnableAuthMethod(ctx context.Context, mount string, spec AuthMethodMountSpec, opts ...CallOption) error
	TuneAuthMethod(ctx context.Context, mount string, spec AuthMethodMountSpec, opts ...CallOption) error
	GetAuthMethod(ctx context.Context, mount string, opts ...CallOption) (*AuthMethodMount, error)

	// OpenBao-namespace lifecycle (sys/namespaces/<name>). Used by the
	// OpenBaoNamespace controller. Nested namespaces are addressed via
	// WithNamespace on the parent context, so spec.name stays a single
	// segment in the CRD even for `acme/sub` (parent="acme/", name="sub").
	CreateNamespace(ctx context.Context, name string, opts ...CallOption) error
	GetNamespace(ctx context.Context, name string, opts ...CallOption) (*Namespace, error)
	DeleteNamespace(ctx context.Context, name string, opts ...CallOption) error

	UpsertPolicy(ctx context.Context, name, rules string, opts ...CallOption) error
	GetPolicy(ctx context.Context, name string, opts ...CallOption) (string, error)
	DeletePolicy(ctx context.Context, name string, opts ...CallOption) error

	UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec, opts ...CallOption) error
	GetK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) (*K8sRole, error)
	DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) error

	// PKI secret-engine config (post-mount). GenerateRootPKI is
	// destructive — calling it on a mount that already has a CA
	// overwrites the private key. Callers must guard with ReadPKICA
	// (returns ErrNotFound when no CA is present).
	GenerateRootPKI(ctx context.Context, mount string, in PKIRootGenerateInput, opts ...CallOption) (*PKICAResponse, error)
	ReadPKICA(ctx context.Context, mount string, opts ...CallOption) (*PKICAResponse, error)
	WritePKIURLs(ctx context.Context, mount string, in PKIURLsInput, opts ...CallOption) error
	ReadPKIURLs(ctx context.Context, mount string, opts ...CallOption) (*PKIURLsInput, error)

	// PKI roles (post-mount, post-CA). Roles define what certs may be
	// issued from a given PKI mount.
	WritePKIRole(ctx context.Context, mount, name string, spec PKIRoleSpec, opts ...CallOption) error
	ReadPKIRole(ctx context.Context, mount, name string, opts ...CallOption) (*PKIRoleSpec, error)
	DeletePKIRole(ctx context.Context, mount, name string, opts ...CallOption) error

	// Identity groups (identity/group). Groups bundle policies + members
	// (entities or other groups for type=internal, alias for type=external).
	// Bao writes by POSTing to identity/group with name in body; reads at
	// identity/group/name/<name>; deletes at identity/group/name/<name>.
	// Create returns the bao-side group id.
	WriteIdentityGroup(ctx context.Context, spec IdentityGroupSpec, opts ...CallOption) (*IdentityGroup, error)
	ReadIdentityGroup(ctx context.Context, name string, opts ...CallOption) (*IdentityGroup, error)
	DeleteIdentityGroup(ctx context.Context, name string, opts ...CallOption) error

	// Identity group aliases (identity/group-alias). A group-alias maps a
	// (name, mount_accessor) tuple from an external auth method to a parent
	// type=external Group. Bao keys aliases by id, so the controller stamps
	// the returned id on status and uses it for subsequent reads/deletes.
	WriteIdentityGroupAlias(ctx context.Context, spec IdentityGroupAliasSpec, opts ...CallOption) (*IdentityGroupAlias, error)
	ReadIdentityGroupAliasByID(ctx context.Context, id string, opts ...CallOption) (*IdentityGroupAlias, error)
	FindIdentityGroupAlias(ctx context.Context, name, mountAccessor string, opts ...CallOption) (*IdentityGroupAlias, error)
	DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...CallOption) error

	// Identity OIDC roles (identity/oidc/role/<name>). Mints OIDC ID tokens
	// signed by a key at identity/oidc/key/<key>. The key is assumed to
	// exist (managed out of band today) — the role write fails with a 4xx
	// if the key is missing.
	WriteIdentityTokenRole(ctx context.Context, name string, spec IdentityTokenRoleSpec, opts ...CallOption) error
	ReadIdentityTokenRole(ctx context.Context, name string, opts ...CallOption) (*IdentityTokenRoleSpec, error)
	DeleteIdentityTokenRole(ctx context.Context, name string, opts ...CallOption) error

	// Cert auth mount-level config (auth/<mount>/config). OCSP settings,
	// identity alias metadata, and other mount-wide tunables. Distinct
	// from per-cert roles below.
	WriteCertAuthConfig(ctx context.Context, mount string, spec CertAuthConfigSpec, opts ...CallOption) error
	ReadCertAuthConfig(ctx context.Context, mount string, opts ...CallOption) (*CertAuthConfigSpec, error)

	// Cert auth roles (auth/<mount>/certs/<name>). The per-cert
	// registration: trusted CA bundle + allow-list (SAN/CN patterns) +
	// the policies it grants. Spec fields the wrapper surfaces are
	// documented on CertAuthRoleSpec; bao defaults fill in the rest.
	WriteCertAuthRole(ctx context.Context, mount, name string, spec CertAuthRoleSpec, opts ...CallOption) error
	ReadCertAuthRole(ctx context.Context, mount, name string, opts ...CallOption) (*CertAuthRoleSpec, error)
	DeleteCertAuthRole(ctx context.Context, mount, name string, opts ...CallOption) error

	// JWT/OIDC auth (auth/<mount>/config). The auth-method-level
	// configuration: discovery URL or static JWKS, default role, etc.
	// Roles for this auth method are at auth/<mount>/role/<name>.
	WriteJWTOIDCConfig(ctx context.Context, mount string, spec JWTOIDCConfigSpec, opts ...CallOption) error
	ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...CallOption) (*JWTOIDCConfigSpec, error)

	WriteJWTOIDCRole(ctx context.Context, mount, name string, spec JWTOIDCRoleSpec, opts ...CallOption) error
	ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...CallOption) (*JWTOIDCRoleSpec, error)
	DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...CallOption) error
}

// CertAuthConfigSpec is the write payload for auth/<mount>/config on
// the cert auth method. All fields are pointers / zero-elidable so
// bao defaults stay in effect when the spec doesn't override them.
type CertAuthConfigSpec struct {
	DisableBinding              *bool
	EnableIdentityAliasMetadata *bool
	OCSPCacheSize               *int
	OCSPFailOpen                *bool
	OCSPQueryAllServers         *bool
}

// CertAuthRoleSpec is the write payload for auth/<mount>/certs/<name>.
// Certificate is the trusted CA bundle in PEM. AllowedNames /
// AllowedCommonNames / AllowedDNSSANs / AllowedURISANs / AllowedEmails
// are bao's filter lists; an empty list means "no filter on this
// dimension" (bao default). TokenPolicies is the policy list bao
// grants on a successful login. TTL fields are bao duration strings.
type CertAuthRoleSpec struct {
	Certificate          string
	DisplayName          string
	AllowedNames         []string
	AllowedCommonNames   []string
	AllowedDNSSANs       []string
	AllowedEmailSANs     []string
	AllowedURISANs       []string
	AllowedOrganizations []string
	RequiredExtensions   []string
	TokenPolicies        []string
	TokenTTL             string
	TokenMaxTTL          string
	TokenPeriod          string
	TokenBoundCIDRs      []string
}

// JWTOIDCConfigSpec is the write payload for auth/<mount>/config on
// JWT and OIDC auth methods. JWKsURL / JWKsCAPEM / OIDCDiscoveryURL /
// OIDCDiscoveryCAPEM are mutually-exclusive ways to tell bao how to
// validate inbound tokens. JWTValidationPubkeys is for static keys.
type JWTOIDCConfigSpec struct {
	OIDCDiscoveryURL     string
	OIDCDiscoveryCAPEM   string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCResponseMode     string
	OIDCResponseTypes    []string
	JWKsURL              string
	JWKsCAPEM            string
	JWTValidationPubkeys []string
	JWTSupportedAlgs     []string
	BoundIssuer          string
	DefaultRole          string
}

// JWTOIDCRoleSpec is the write payload for auth/<mount>/role/<name>
// on JWT and OIDC auth methods. RoleType is "jwt" or "oidc"; the
// remaining fields parametrise how bao maps an inbound token's claims
// to bao policies + identity.
type JWTOIDCRoleSpec struct {
	RoleType             string
	UserClaim            string
	UserClaimJSONPointer *bool
	BoundAudiences       []string
	BoundSubject         string
	BoundClaimsType      string
	BoundClaims          map[string]interface{}
	GroupsClaim          string
	ClaimMappings        map[string]string
	OIDCScopes           []string
	AllowedRedirectURIs  []string
	VerboseOIDCLogging   *bool
	TokenPolicies        []string
	TokenTTL             string
	TokenMaxTTL          string
	TokenBoundCIDRs      []string
}

// IdentityGroupSpec is the write payload for identity/group. Type is
// "internal" (default) or "external"; only external groups can have
// aliases. Policies / MemberGroupIDs / MemberEntityIDs are only
// meaningful for internal groups (bao silently rejects them on
// external groups). The ID field is used to update an existing group
// in place — leave empty on create; bao returns the id which the
// controller round-trips on subsequent writes.
type IdentityGroupSpec struct {
	ID              string
	Name            string
	Type            string
	Policies        []string
	MemberGroupIDs  []string
	MemberEntityIDs []string
	Metadata        map[string]string
}

// IdentityGroup is the read shape returned by identity/group/name/<name>.
// Only the fields the controller's drift comparator and consumers
// actually use are surfaced — bao echoes additional fields
// (modify_index, creation_time, namespace_id, parent_group_ids) that
// would trigger spurious drift if they were compared without
// normalization.
type IdentityGroup struct {
	ID              string
	Name            string
	Type            string
	Policies        []string
	MemberGroupIDs  []string
	MemberEntityIDs []string
	Metadata        map[string]string
}

// IdentityGroupAliasSpec is the write payload for identity/group-alias.
// CanonicalID is the parent Group's bao id; MountAccessor is the auth
// mount accessor the alias maps from. ID is used to update an existing
// alias in place.
type IdentityGroupAliasSpec struct {
	ID            string
	Name          string
	MountAccessor string
	CanonicalID   string
}

// IdentityGroupAlias is the read shape for identity/group-alias/id/<id>.
type IdentityGroupAlias struct {
	ID            string
	Name          string
	MountAccessor string
	CanonicalID   string
}

// IdentityTokenRoleSpec is the write payload for identity/oidc/role/<name>.
// Key names a pre-existing OIDC key at identity/oidc/key/<key>. Template
// is the JWT claims template (base64-or-plain-JSON per bao docs).
// ClientID is the audience claim. TTL is a bao duration string.
type IdentityTokenRoleSpec struct {
	Key      string
	Template string
	ClientID string
	TTL      string
}

// PKIRoleSpec mirrors the bao API surface for /<mount>/roles/<name>.
// Fields the controller doesn't currently surface in the CR spec are
// added as the spec grows; bao defaults fill in the rest.
type PKIRoleSpec struct {
	AllowedDomains   []string
	AllowSubdomains  bool
	AllowBareDomains bool
	AllowAnyName     bool
	EnforceHostnames bool
	AllowIPSANs      bool
	AllowGlobDomains bool
	ServerFlag       bool
	ClientFlag       bool
	CodeSigningFlag  bool
	EmailProtection  bool
	KeyType          string // rsa | ec | ed25519 | any
	KeyBits          int
	KeyUsage         []string
	ExtKeyUsage      []string
	TTL              string
	MaxTTL           string
	GenerateLease    bool
	NoStore          bool
	RequireCN        bool
}

// PKIRootGenerateInput is the body for /<mount>/root/generate/internal.
// Only the fields the controller currently exposes through the CR spec
// are present; expand as the spec grows.
type PKIRootGenerateInput struct {
	CommonName       string
	TTL              string
	KeyType          string // rsa | ec | ed25519
	KeyBits          int
	Country          []string
	Locality         []string
	Province         []string
	StreetAddress    []string
	PostalCode       []string
	Organization     []string
	OU               []string
	MaxPathLength    int
	ExcludeCNFromSAN bool
}

// PKICAResponse captures the bao-side data we surface to the controller.
type PKICAResponse struct {
	SerialNumber string
	Certificate  string // PEM
}

// PKIURLsInput / response carry the AIA/CRL distribution metadata.
type PKIURLsInput struct {
	IssuingCertificates   []string
	CRLDistributionPoints []string
	OCSPServers           []string
}

// SecretEngineMountSpec is the write payload for EnableSecretEngine.
// Mirrors the shape vault/api's MountInput exposes — bao stores the same
// fields. Description and Options are nullable on the bao side; we send
// non-empty values only.
type SecretEngineMountSpec struct {
	Type        string
	Description string
	// Options is the engine-specific options map. For kv-v2 the canonical
	// content is {"version": "2"}.
	Options map[string]string
}

// SecretEngineMount is the read shape for GetSecretEngineMount. Stripped
// down from vault/api's MountOutput to the fields the operator's drift
// comparator actually consumes; bao still echoes the rest, but reading
// them here would invite false drift on every server upgrade.
type SecretEngineMount struct {
	Type        string
	Description string
	Options     map[string]string
}

// AuthMount is the read shape for GetAuthMount.
type AuthMount struct {
	Type        string
	Description string
}

// AuthMethodMountSpec is the write payload for EnableAuthMethod and
// TuneAuthMethod. Mirrors bao's sys/auth POST shape: type is
// mount-immutable; description and config are tunable. Config holds
// the fields under MountConfigInput on bao's tune endpoint
// (default_lease_ttl, max_lease_ttl, listing_visibility, …); only
// non-zero values are emitted on the wire so bao's defaults stay in
// effect when the spec doesn't override them.
type AuthMethodMountSpec struct {
	Type        string
	Description string
	Config      AuthMethodConfig
}

// AuthMethodMount is the read shape returned by GetAuthMethod. Type
// is the bao-side wire string ("kubernetes", "jwt", "cert", …);
// description is the free-form mount description; config carries
// any tunable mount-config values bao echoes on read; accessor is
// the bao-side mount accessor identity-group aliases bind to.
type AuthMethodMount struct {
	Type        string
	Description string
	Accessor    string
	Config      AuthMethodConfig
}

// AuthMethodConfig is the subset of bao's MountConfigInput the
// operator's drift comparator actually consumes. Empty / zero values
// are elided from the wire body so a spec that doesn't pin them
// doesn't override bao's mount defaults. TTL fields are bao
// duration strings ("1h", "3600s") on the spec side; the wrapper
// normalises bao's int-second response back to <n>s on read.
type AuthMethodConfig struct {
	DefaultLeaseTTL   string
	MaxLeaseTTL       string
	ListingVisibility string
}

// Namespace is the read shape for GetNamespace. Bao echoes more fields
// (custom_metadata, etc.); we keep just what the operator's drift /
// existence checks need. Path is the fully-qualified bao-side path
// including any parent prefix.
type Namespace struct {
	Path string
	ID   string
}

// ErrNotFound is the sentinel returned by every Get* when the object does
// not exist on the bao side. Callers use errors.Is to match.
var ErrNotFound = errors.New("bao object not found")

// CallOption configures a single bao API call. The only option today is
// WithNamespace, which scopes the call to an OpenBao namespace via the
// X-Vault-Namespace header. The variadic shape is forward-compatible: future
// options (timeout overrides, custom headers) can be added without breaking
// existing call sites.
type CallOption func(*callOpts)

type callOpts struct {
	namespace string
}

// WithNamespace scopes the call to an OpenBao namespace (e.g. "acme/" or
// "acme/sub/"). An empty string is equivalent to passing no option — the call
// targets the root namespace. The trailing slash is conventional but not
// required; bao accepts both forms.
func WithNamespace(ns string) CallOption {
	return func(o *callOpts) { o.namespace = ns }
}

// NamespaceFromOpts returns the namespace selected by the supplied call
// options, or "" if no namespace was requested. Exists so test fakes that
// implement Client can mirror the real client's per-call namespace routing
// without reaching into unexported types. Production callers should not
// need this — they pass WithNamespace into the call directly.
func NamespaceFromOpts(opts []CallOption) string {
	var o callOpts
	for _, fn := range opts {
		fn(&o)
	}
	return o.namespace
}

// K8sRoleSpec is the write payload for a Kubernetes auth role. Fields use
// pointer / empty-string sentinels for "unset" so UpsertK8sRole can omit
// keys that the caller did not set — bao distinguishes between "field
// absent" (use mount default) and "field present with zero value" (override
// with that value, e.g. token_num_uses=0 means unlimited).
type K8sRoleSpec struct {
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	TokenTTL                      string
	TokenMaxTTL                   string
	Renewable                     *bool

	// Fields below were added for the KubernetesAuthEngineRole CRD; the
	// Tenant controller leaves them at zero values and they are omitted
	// from the bao request, preserving its historical request shape.
	Audience             string
	AliasNameSource      string
	TokenBoundCIDRs      []string
	TokenExplicitMaxTTL  string
	TokenNoDefaultPolicy *bool
	TokenNumUses         *int
	TokenPeriod          string
	TokenType            string
}

type K8sRole struct {
	Name                          string
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	TokenTTL                      string
	TokenMaxTTL                   string
	Renewable                     *bool

	Audience             string
	AliasNameSource      string
	TokenBoundCIDRs      []string
	TokenExplicitMaxTTL  string
	TokenNoDefaultPolicy *bool
	TokenNumUses         *int
	TokenPeriod          string
	TokenType            string
}

// StatusError wraps an SDK error that carries an HTTP status code. The shared
// reconcile base classifies bao errors by status (403 → Forbidden,
// 404 → NotFound) via errors.As; consolidating the translation here keeps
// callers free of fragile string-matching against error messages, which
// would misclassify e.g. a 500 whose body contains "upstream service not found".
type StatusError struct {
	StatusCode int
	Inner      error
}

func (e *StatusError) Error() string { return e.Inner.Error() }
func (e *StatusError) Unwrap() error { return e.Inner }

// wrapStatus translates SDK-specific *vault.ResponseError into our local
// StatusError. Non-status errors (network, context-cancelled, etc.) pass
// through unchanged.
func wrapStatus(err error) error {
	if err == nil {
		return nil
	}
	var rerr *vault.ResponseError
	if errors.As(err, &rerr) {
		return &StatusError{StatusCode: rerr.StatusCode, Inner: err}
	}
	return err
}

// ---- SDK-backed implementation. ----

type sdkClient struct {
	v *vault.Client
}

// NewHTTPClient constructs a Client backed by hashicorp/vault/api. It
// returns an error rather than a degraded client so misconfiguration
// (empty address, malformed config) surfaces at construction time instead
// of as repeated reconcile-time failures with no diagnostic for the
// operator process itself.
func NewHTTPClient(addr, token string) (Client, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, fmt.Errorf("bao client: address is empty")
	}
	cfg := vault.DefaultConfig()
	cfg.Address = strings.TrimRight(addr, "/")
	v, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("bao client: %w", err)
	}
	v.SetToken(token)
	return &sdkClient{v: v}, nil
}

// underlying is a package-private accessor used by tests in this package.
// Exposing the raw *vault.Client externally would let callers bypass the
// wrapper's status-classification and idempotency contracts, defeating
// the abstraction; the lowercase name keeps the escape hatch in-package
// where compile-time checks catch misuse.
func (c *sdkClient) underlying() *vault.Client { return c.v }

// clientFor returns the vault client to use for this call: either the shared
// top-level client (no opts, or empty namespace) or a derived client with
// X-Vault-Namespace set. Allocating a per-call client only when opts ask for
// it keeps the hot path (root-namespace calls) allocation-free.
func (c *sdkClient) clientFor(opts []CallOption) *vault.Client {
	if len(opts) == 0 {
		return c.v
	}
	var o callOpts
	for _, fn := range opts {
		fn(&o)
	}
	if o.namespace == "" {
		return c.v
	}
	return c.v.WithNamespace(o.namespace)
}

// ---- Mounts ----

func (c *sdkClient) CheckKVv2Mount(ctx context.Context, mount string, opts ...CallOption) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	mounts, err := c.clientFor(opts).Sys().ListMountsWithContext(ctx)
	if err != nil {
		return false, wrapStatus(err)
	}
	m, ok := mounts[mount]
	if !ok {
		return false, nil
	}
	return m.Type == "kv" && m.Options["version"] == "2", nil
}

func (c *sdkClient) CheckAuthMount(ctx context.Context, mount string, opts ...CallOption) (bool, error) {
	mount = strings.Trim(mount, "/") + "/"
	auths, err := c.clientFor(opts).Sys().ListAuthWithContext(ctx)
	if err != nil {
		return false, wrapStatus(err)
	}
	m, ok := auths[mount]
	if !ok {
		return false, nil
	}
	return m.Type == "kubernetes", nil
}

func (c *sdkClient) EnableAuthMount(ctx context.Context, mount, typ string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	if typ == "" {
		return errors.New("auth type is empty")
	}
	err := c.clientFor(opts).Sys().EnableAuthWithOptionsWithContext(ctx, mount, &vault.EnableAuthOptions{Type: typ})
	if err != nil && isAlreadyInUse(err) {
		return nil
	}
	return wrapStatus(err)
}

func (c *sdkClient) EnableSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	if spec.Type == "" {
		return errors.New("mount type is empty")
	}
	input := &vault.MountInput{
		Type:        spec.Type,
		Description: spec.Description,
		Options:     spec.Options,
	}
	err := c.clientFor(opts).Sys().MountWithContext(ctx, mount, input)
	if err != nil && isAlreadyInUse(err) {
		// Idempotent enable: a mount already at this path with a different
		// type would have surfaced as a different bao error earlier in the
		// reconciler's Get → IsEquivalent → Write path; the only "already
		// in use" we see here is when our own previous reconcile succeeded.
		return nil
	}
	return wrapStatus(err)
}

// TuneSecretEngine updates tunable fields on an existing mount via
// POST /sys/mounts/<path>/tune. Bao's enable endpoint does not update
// an existing mount (it returns 400 "path already in use"), so the
// controller calls this on the update path. Description and Options
// are sent verbatim — Type is mount-immutable and ignored here.
func (c *sdkClient) TuneSecretEngine(ctx context.Context, mount string, spec SecretEngineMountSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	input := vault.MountConfigInput{
		Description: &spec.Description,
		Options:     spec.Options,
	}
	err := c.clientFor(opts).Sys().TuneMountWithContext(ctx, mount, input)
	return wrapStatus(err)
}

func (c *sdkClient) GetSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) (*SecretEngineMount, error) {
	mount = strings.Trim(mount, "/") + "/"
	mounts, err := c.clientFor(opts).Sys().ListMountsWithContext(ctx)
	if err != nil {
		return nil, wrapStatus(err)
	}
	m, ok := mounts[mount]
	if !ok {
		return nil, ErrNotFound
	}
	return &SecretEngineMount{
		Type:        m.Type,
		Description: m.Description,
		Options:     m.Options,
	}, nil
}

func (c *sdkClient) DisableSecretEngineMount(ctx context.Context, mount string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	err := c.clientFor(opts).Sys().UnmountWithContext(ctx, mount)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent: 404 = already gone. Mirrors DeletePolicy.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

func (c *sdkClient) GetAuthMount(ctx context.Context, mount string, opts ...CallOption) (*AuthMount, error) {
	mount = strings.Trim(mount, "/") + "/"
	auths, err := c.clientFor(opts).Sys().ListAuthWithContext(ctx)
	if err != nil {
		return nil, wrapStatus(err)
	}
	m, ok := auths[mount]
	if !ok {
		return nil, ErrNotFound
	}
	return &AuthMount{
		Type:        m.Type,
		Description: m.Description,
	}, nil
}

// EnableAuthMethod creates a sys/auth mount with the given type +
// description + tunable config. Idempotent on "path already in use" —
// callers route to TuneAuthMethod on the update path instead of
// re-calling EnableAuthMethod, since bao's POST sys/auth endpoint
// creates only.
func (c *sdkClient) EnableAuthMethod(ctx context.Context, mount string, spec AuthMethodMountSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("auth mount path is empty")
	}
	if spec.Type == "" {
		return errors.New("auth mount type is empty")
	}
	input := &vault.EnableAuthOptions{
		Type:        spec.Type,
		Description: spec.Description,
		Config:      authMethodConfigToInput(spec.Config),
	}
	err := c.clientFor(opts).Sys().EnableAuthWithOptionsWithContext(ctx, mount, input)
	if err != nil && isAlreadyInUse(err) {
		return nil
	}
	return wrapStatus(err)
}

// TuneAuthMethod updates a sys/auth mount's tunable fields via
// POST /sys/auth/<path>/tune. Type is mount-immutable and ignored
// on this path; description + config are sent verbatim. Empty
// description on the spec clears bao's stored description (matches
// bao's POST semantics — present field overrides previous value).
func (c *sdkClient) TuneAuthMethod(ctx context.Context, mount string, spec AuthMethodMountSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("auth mount path is empty")
	}
	desc := spec.Description
	input := vault.MountConfigInput{
		Description: &desc,
	}
	if spec.Config.DefaultLeaseTTL != "" {
		input.DefaultLeaseTTL = spec.Config.DefaultLeaseTTL
	}
	if spec.Config.MaxLeaseTTL != "" {
		input.MaxLeaseTTL = spec.Config.MaxLeaseTTL
	}
	if spec.Config.ListingVisibility != "" {
		input.ListingVisibility = spec.Config.ListingVisibility
	}
	err := c.clientFor(opts).Sys().TuneMountWithContext(ctx, "auth/"+mount, input)
	return wrapStatus(err)
}

// GetAuthMethod returns the rich auth-mount read shape (type +
// description + tunable config). GetAuthMount above stays — it's
// what ClusterAuth uses and adding the config fields would change
// its return shape. Callers wanting drift comparison against tunable
// fields use this method.
func (c *sdkClient) GetAuthMethod(ctx context.Context, mount string, opts ...CallOption) (*AuthMethodMount, error) {
	mount = strings.Trim(mount, "/") + "/"
	auths, err := c.clientFor(opts).Sys().ListAuthWithContext(ctx)
	if err != nil {
		return nil, wrapStatus(err)
	}
	m, ok := auths[mount]
	if !ok {
		return nil, ErrNotFound
	}
	return &AuthMethodMount{
		Type:        m.Type,
		Description: m.Description,
		Accessor:    m.Accessor,
		Config:      authMethodConfigFromOutput(m.Config),
	}, nil
}

// authMethodConfigToInput converts the operator's wire-shape struct
// into vault/api's MountConfigInput. Used on enable.
func authMethodConfigToInput(c AuthMethodConfig) vault.MountConfigInput {
	return vault.MountConfigInput{
		DefaultLeaseTTL:   c.DefaultLeaseTTL,
		MaxLeaseTTL:       c.MaxLeaseTTL,
		ListingVisibility: c.ListingVisibility,
	}
}

// authMethodConfigFromOutput reverses authMethodConfigToInput for
// drift comparisons. TTL fields come back as int seconds via
// MountConfigOutput; render as <n>s for stable round-trip with
// the spec's bao-duration string.
func authMethodConfigFromOutput(o vault.MountConfigOutput) AuthMethodConfig {
	out := AuthMethodConfig{
		ListingVisibility: o.ListingVisibility,
	}
	if o.DefaultLeaseTTL > 0 {
		out.DefaultLeaseTTL = fmt.Sprintf("%ds", o.DefaultLeaseTTL)
	}
	if o.MaxLeaseTTL > 0 {
		out.MaxLeaseTTL = fmt.Sprintf("%ds", o.MaxLeaseTTL)
	}
	return out
}

func (c *sdkClient) DisableAuthMount(ctx context.Context, mount string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("mount path is empty")
	}
	err := c.clientFor(opts).Sys().DisableAuthWithContext(ctx, mount)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- OpenBao namespaces (sys/namespaces/<name>) ----
//
// vault/api OSS does not expose Sys() helpers for namespaces (Vault treats
// them as Enterprise), so these go through Logical() against the
// sys/namespaces/ paths directly. The wire shape is identical to bao's
// HTTP API.

func (c *sdkClient) CreateNamespace(ctx context.Context, name string, opts ...CallOption) error {
	name = strings.Trim(name, "/")
	if name == "" {
		return errors.New("namespace name is empty")
	}
	// Bao's POST sys/namespaces/<name> is idempotent: re-creating an
	// existing namespace returns success and does not change its ID.
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "sys/namespaces/"+name, nil)
	return wrapStatus(err)
}

func (c *sdkClient) GetNamespace(ctx context.Context, name string, opts ...CallOption) (*Namespace, error) {
	name = strings.Trim(name, "/")
	if name == "" {
		return nil, errors.New("namespace name is empty")
	}
	sec, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "sys/namespaces/"+name)
	if err != nil {
		return nil, wrapStatus(err)
	}
	if sec == nil || sec.Data == nil {
		return nil, ErrNotFound
	}
	return &Namespace{
		Path: asString(sec.Data["path"]),
		ID:   asString(sec.Data["id"]),
	}, nil
}

func (c *sdkClient) DeleteNamespace(ctx context.Context, name string, opts ...CallOption) error {
	name = strings.Trim(name, "/")
	if name == "" {
		return errors.New("namespace name is empty")
	}
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, "sys/namespaces/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent delete: 404 = already gone. Mirrors DeletePolicy.
	// 400-class responses for "namespace contains children" surface as
	// regular bao errors and the finalizer stays in place — exactly the
	// graceful-block behaviour the controller wants.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- Policies ----

func (c *sdkClient) UpsertPolicy(ctx context.Context, name, rules string, opts ...CallOption) error {
	return wrapStatus(c.clientFor(opts).Sys().PutPolicyWithContext(ctx, name, rules))
}

func (c *sdkClient) GetPolicy(ctx context.Context, name string, opts ...CallOption) (string, error) {
	// vault/api swallows 404 internally and returns ("", nil) for missing
	// policies. We translate that to ErrNotFound so callers get a uniform
	// missing signal across the interface. An empty-but-present policy is
	// indistinguishable from missing here; callers that care must guard
	// against ever writing an empty body (see Policy.IsValid).
	body, err := c.clientFor(opts).Sys().GetPolicyWithContext(ctx, name)
	if err != nil {
		return "", wrapStatus(err)
	}
	if body == "" {
		return "", ErrNotFound
	}
	return body, nil
}

func (c *sdkClient) DeletePolicy(ctx context.Context, name string, opts ...CallOption) error {
	err := c.clientFor(opts).Sys().DeletePolicyWithContext(ctx, name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent delete: 404 = already gone.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- Kubernetes auth roles ----

func (c *sdkClient) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec K8sRoleSpec, opts ...CallOption) error {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	data := map[string]any{
		"token_policies":                   spec.Policies,
		"bound_service_account_names":      spec.BoundServiceAccountNames,
		"bound_service_account_namespaces": spec.BoundServiceAccountNamespaces,
	}
	if spec.TokenTTL != "" {
		data["token_ttl"] = spec.TokenTTL
	}
	if spec.TokenMaxTTL != "" {
		data["token_max_ttl"] = spec.TokenMaxTTL
	}
	if spec.Renewable != nil {
		data["token_renewable"] = *spec.Renewable
	}
	if spec.Audience != "" {
		data["audience"] = spec.Audience
	}
	if spec.AliasNameSource != "" {
		data["alias_name_source"] = spec.AliasNameSource
	}
	if len(spec.TokenBoundCIDRs) > 0 {
		data["token_bound_cidrs"] = spec.TokenBoundCIDRs
	}
	if spec.TokenExplicitMaxTTL != "" {
		data["token_explicit_max_ttl"] = spec.TokenExplicitMaxTTL
	}
	if spec.TokenNoDefaultPolicy != nil {
		data["token_no_default_policy"] = *spec.TokenNoDefaultPolicy
	}
	if spec.TokenNumUses != nil {
		data["token_num_uses"] = *spec.TokenNumUses
	}
	if spec.TokenPeriod != "" {
		data["token_period"] = spec.TokenPeriod
	}
	if spec.TokenType != "" {
		data["token_type"] = spec.TokenType
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, path, data)
	return wrapStatus(err)
}

func (c *sdkClient) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) (*K8sRole, error) {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	sec, err := c.clientFor(opts).Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, wrapStatus(err)
	}
	if sec == nil || sec.Data == nil {
		return nil, ErrNotFound
	}
	return &K8sRole{
		Name:                          roleName,
		Policies:                      asStringSlice(sec.Data["token_policies"]),
		BoundServiceAccountNames:      asStringSlice(sec.Data["bound_service_account_names"]),
		BoundServiceAccountNamespaces: asStringSlice(sec.Data["bound_service_account_namespaces"]),
		TokenTTL:                      asString(sec.Data["token_ttl"]),
		TokenMaxTTL:                   asString(sec.Data["token_max_ttl"]),
		Renewable:                     asBoolPtr(sec.Data["token_renewable"]),
		Audience:                      asString(sec.Data["audience"]),
		AliasNameSource:               asString(sec.Data["alias_name_source"]),
		TokenBoundCIDRs:               asStringSlice(sec.Data["token_bound_cidrs"]),
		TokenExplicitMaxTTL:           asString(sec.Data["token_explicit_max_ttl"]),
		TokenNoDefaultPolicy:          asBoolPtr(sec.Data["token_no_default_policy"]),
		TokenNumUses:                  asIntPtr(sec.Data["token_num_uses"]),
		TokenPeriod:                   asString(sec.Data["token_period"]),
		TokenType:                     asString(sec.Data["token_type"]),
	}, nil
}

func (c *sdkClient) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...CallOption) error {
	path := fmt.Sprintf("auth/%s/role/%s", strings.Trim(authMount, "/"), roleName)
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, path)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	// Idempotent delete: 404 = already gone. Mirrors DeletePolicy.
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- PKI ----

// GenerateRootPKI calls /<mount>/root/generate/internal. DESTRUCTIVE on
// a mount that already has a CA — bao silently overwrites the private
// key. Callers must guard via ReadPKICA first.
func (c *sdkClient) GenerateRootPKI(ctx context.Context, mount string, in PKIRootGenerateInput, opts ...CallOption) (*PKICAResponse, error) {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return nil, errors.New("mount path is empty")
	}
	if strings.TrimSpace(in.CommonName) == "" {
		return nil, errors.New("common_name is required")
	}
	body := map[string]interface{}{"common_name": in.CommonName}
	if in.TTL != "" {
		body["ttl"] = in.TTL
	}
	if in.KeyType != "" {
		body["key_type"] = in.KeyType
	}
	if in.KeyBits > 0 {
		body["key_bits"] = in.KeyBits
	}
	if len(in.Country) > 0 {
		body["country"] = in.Country
	}
	if len(in.Locality) > 0 {
		body["locality"] = in.Locality
	}
	if len(in.Province) > 0 {
		body["province"] = in.Province
	}
	if len(in.StreetAddress) > 0 {
		body["street_address"] = in.StreetAddress
	}
	if len(in.PostalCode) > 0 {
		body["postal_code"] = in.PostalCode
	}
	if len(in.Organization) > 0 {
		body["organization"] = in.Organization
	}
	if len(in.OU) > 0 {
		body["ou"] = in.OU
	}
	if in.MaxPathLength != 0 {
		body["max_path_length"] = in.MaxPathLength
	}
	if in.ExcludeCNFromSAN {
		body["exclude_cn_from_sans"] = true
	}
	path := mount + "/root/generate/internal"
	resp, err := c.clientFor(opts).Logical().WriteWithContext(ctx, path, body)
	if err != nil {
		return nil, wrapStatus(err)
	}
	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("empty response from %s", path)
	}
	return &PKICAResponse{
		SerialNumber: asString(resp.Data["serial_number"]),
		Certificate:  asString(resp.Data["certificate"]),
	}, nil
}

// ReadPKICA fetches the active CA cert at <mount>/cert/ca. Returns
// ErrNotFound when no CA has been generated yet — bao reports this in
// three different shapes depending on version: 404, 200 with empty
// data, or 400 with the message "no default issuer currently
// configured". We coalesce all three into the canonical not-found
// signal so the controller's "needs create" branch fires
// consistently.
func (c *sdkClient) ReadPKICA(ctx context.Context, mount string, opts ...CallOption) (*PKICAResponse, error) {
	mount = strings.Trim(mount, "/")
	path := mount + "/cert/ca"
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, path)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		// OpenBao 2.x returns 400 + "no default issuer" when the mount
		// is empty. Treat as not-found so the create path fires.
		if strings.Contains(strings.ToLower(err.Error()), "no default issuer") {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	cert := asString(resp.Data["certificate"])
	if cert == "" {
		return nil, ErrNotFound
	}
	return &PKICAResponse{
		SerialNumber: asString(resp.Data["serial_number"]),
		Certificate:  cert,
	}, nil
}

// WritePKIURLs configures the AIA / CRL / OCSP distribution points
// published in every issued cert via <mount>/config/urls. Idempotent.
func (c *sdkClient) WritePKIURLs(ctx context.Context, mount string, in PKIURLsInput, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	body := map[string]interface{}{
		"issuing_certificates":    in.IssuingCertificates,
		"crl_distribution_points": in.CRLDistributionPoints,
		"ocsp_servers":            in.OCSPServers,
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, mount+"/config/urls", body)
	return wrapStatus(err)
}

// ReadPKIURLs returns the URL config; nil-pointer fields when bao has
// no URLs configured (returns 200 with empty arrays).
func (c *sdkClient) ReadPKIURLs(ctx context.Context, mount string, opts ...CallOption) (*PKIURLsInput, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, mount+"/config/urls")
	if err != nil {
		return nil, wrapStatus(err)
	}
	if resp == nil || resp.Data == nil {
		return &PKIURLsInput{}, nil
	}
	return &PKIURLsInput{
		IssuingCertificates:   asStringSlice(resp.Data["issuing_certificates"]),
		CRLDistributionPoints: asStringSlice(resp.Data["crl_distribution_points"]),
		OCSPServers:           asStringSlice(resp.Data["ocsp_servers"]),
	}, nil
}

// WritePKIRole upserts a role at /<mount>/roles/<name>. Bao writes are
// idempotent on the path; calling twice with the same body is a no-op.
func (c *sdkClient) WritePKIRole(ctx context.Context, mount, name string, spec PKIRoleSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" || name == "" {
		return errors.New("mount or role name empty")
	}
	body := pkiRoleToMap(spec)
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, mount+"/roles/"+name, body)
	return wrapStatus(err)
}

// ReadPKIRole fetches the role config. Returns ErrNotFound on 404 or
// 200 with empty data.
func (c *sdkClient) ReadPKIRole(ctx context.Context, mount, name string, opts ...CallOption) (*PKIRoleSpec, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, mount+"/roles/"+name)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	return mapToPKIRole(resp.Data), nil
}

// DeletePKIRole removes a role. Idempotent on 404.
func (c *sdkClient) DeletePKIRole(ctx context.Context, mount, name string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, mount+"/roles/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// pkiRoleToMap builds the bao write body from a PKIRoleSpec. Only
// non-zero fields are emitted so bao's defaults stay in effect when
// the CR doesn't override them.
func pkiRoleToMap(s PKIRoleSpec) map[string]interface{} {
	body := map[string]interface{}{}
	if len(s.AllowedDomains) > 0 {
		body["allowed_domains"] = s.AllowedDomains
	}
	if s.AllowSubdomains {
		body["allow_subdomains"] = true
	}
	if s.AllowBareDomains {
		body["allow_bare_domains"] = true
	}
	if s.AllowAnyName {
		body["allow_any_name"] = true
	}
	if s.EnforceHostnames {
		body["enforce_hostnames"] = true
	}
	if s.AllowIPSANs {
		body["allow_ip_sans"] = true
	}
	if s.AllowGlobDomains {
		body["allow_glob_domains"] = true
	}
	if s.ServerFlag {
		body["server_flag"] = true
	}
	if s.ClientFlag {
		body["client_flag"] = true
	}
	if s.CodeSigningFlag {
		body["code_signing_flag"] = true
	}
	if s.EmailProtection {
		body["email_protection_flag"] = true
	}
	if s.KeyType != "" {
		body["key_type"] = s.KeyType
	}
	if s.KeyBits > 0 {
		body["key_bits"] = s.KeyBits
	}
	if len(s.KeyUsage) > 0 {
		body["key_usage"] = s.KeyUsage
	}
	if len(s.ExtKeyUsage) > 0 {
		body["ext_key_usage"] = s.ExtKeyUsage
	}
	if s.TTL != "" {
		body["ttl"] = s.TTL
	}
	if s.MaxTTL != "" {
		body["max_ttl"] = s.MaxTTL
	}
	if s.GenerateLease {
		body["generate_lease"] = true
	}
	if s.NoStore {
		body["no_store"] = true
	}
	if s.RequireCN {
		body["require_cn"] = true
	}
	return body
}

// mapToPKIRole reverses pkiRoleToMap for drift comparisons. Bao
// echoes server-side defaults (e.g. ttl=0, key_bits=2048) so the read
// shape is richer than the write shape; the comparator on the CR side
// does the normalization.
func mapToPKIRole(d map[string]interface{}) *PKIRoleSpec {
	derefBool := func(v any) bool {
		p := asBoolPtr(v)
		if p == nil {
			return false
		}
		return *p
	}
	derefInt := func(v any) int {
		p := asIntPtr(v)
		if p == nil {
			return 0
		}
		return *p
	}
	// TTL fields come back as bao durations: int seconds. Render as a
	// "<n>s" string so the comparator on the CR side can treat them
	// the same way as the spec's bao-duration string ("1h", "3600s").
	durStr := func(v any) string {
		if p := asIntPtr(v); p != nil {
			if *p == 0 {
				return ""
			}
			return fmt.Sprintf("%ds", *p)
		}
		return asString(v)
	}
	out := &PKIRoleSpec{
		AllowedDomains:   asStringSlice(d["allowed_domains"]),
		AllowSubdomains:  derefBool(d["allow_subdomains"]),
		AllowBareDomains: derefBool(d["allow_bare_domains"]),
		AllowAnyName:     derefBool(d["allow_any_name"]),
		EnforceHostnames: derefBool(d["enforce_hostnames"]),
		AllowIPSANs:      derefBool(d["allow_ip_sans"]),
		AllowGlobDomains: derefBool(d["allow_glob_domains"]),
		ServerFlag:       derefBool(d["server_flag"]),
		ClientFlag:       derefBool(d["client_flag"]),
		CodeSigningFlag:  derefBool(d["code_signing_flag"]),
		EmailProtection:  derefBool(d["email_protection_flag"]),
		KeyType:          asString(d["key_type"]),
		KeyBits:          derefInt(d["key_bits"]),
		KeyUsage:         asStringSlice(d["key_usage"]),
		ExtKeyUsage:      asStringSlice(d["ext_key_usage"]),
		TTL:              durStr(d["ttl"]),
		MaxTTL:           durStr(d["max_ttl"]),
		GenerateLease:    derefBool(d["generate_lease"]),
		NoStore:          derefBool(d["no_store"]),
		RequireCN:        derefBool(d["require_cn"]),
	}
	return out
}

// ---- helpers ----

// isAlreadyInUse stays string-based: bao returns 400 with this message text
// for an idempotent re-enable, not a distinct status code, so we have to
// peek at the message body either way.
func isAlreadyInUse(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already in use") || strings.Contains(msg, "path is already in use")
}

func asStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	if is, ok := v.([]any); ok {
		out := make([]string, 0, len(is))
		for _, it := range is {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func asBoolPtr(v any) *bool {
	if v == nil {
		return nil
	}
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// ---- Identity groups (identity/group, identity/group/name/<name>) ----

// WriteIdentityGroup creates or updates a group at identity/group. Bao
// upserts: a body with no id creates a new group (server-side rejects on
// duplicate name); a body with id updates the existing group. The
// controller round-trips the bao-side id through status to disambiguate.
//
// Returns the created/updated group with the bao-stamped id, so the
// caller can persist the id without an extra Read.
func (c *sdkClient) WriteIdentityGroup(ctx context.Context, spec IdentityGroupSpec, opts ...CallOption) (*IdentityGroup, error) {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		return nil, errors.New("identity group name is empty")
	}
	body := map[string]interface{}{
		"name": name,
	}
	if spec.ID != "" {
		body["id"] = spec.ID
	}
	if spec.Type != "" {
		body["type"] = spec.Type
	}
	if spec.Policies != nil {
		// Send empty slice on purpose so the user can clear all
		// policies on an existing group; otherwise bao would keep
		// the previously-written list.
		body["policies"] = spec.Policies
	}
	if spec.MemberGroupIDs != nil {
		body["member_group_ids"] = spec.MemberGroupIDs
	}
	if spec.MemberEntityIDs != nil {
		body["member_entity_ids"] = spec.MemberEntityIDs
	}
	if spec.Metadata != nil {
		body["metadata"] = spec.Metadata
	}
	resp, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "identity/group", body)
	if err != nil {
		return nil, wrapStatus(err)
	}
	// On id-update, bao returns 204 (nil resp). Round-trip what the
	// caller asked for so status fields remain stable across update
	// reconciles. On create, the response carries the new id and name.
	if resp == nil || resp.Data == nil {
		return &IdentityGroup{
			ID:              spec.ID,
			Name:            name,
			Type:            spec.Type,
			Policies:        append([]string(nil), spec.Policies...),
			MemberGroupIDs:  append([]string(nil), spec.MemberGroupIDs...),
			MemberEntityIDs: append([]string(nil), spec.MemberEntityIDs...),
			Metadata:        copyStringMap(spec.Metadata),
		}, nil
	}
	return &IdentityGroup{
		ID:   asString(resp.Data["id"]),
		Name: asString(resp.Data["name"]),
		// Type/Policies/etc. aren't in the create response; round-trip
		// what the caller specified so the StatusMutator has them.
		Type:            spec.Type,
		Policies:        append([]string(nil), spec.Policies...),
		MemberGroupIDs:  append([]string(nil), spec.MemberGroupIDs...),
		MemberEntityIDs: append([]string(nil), spec.MemberEntityIDs...),
		Metadata:        copyStringMap(spec.Metadata),
	}, nil
}

func (c *sdkClient) ReadIdentityGroup(ctx context.Context, name string, opts ...CallOption) (*IdentityGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("identity group name is empty")
	}
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "identity/group/name/"+name)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	return mapToIdentityGroup(resp.Data), nil
}

func (c *sdkClient) DeleteIdentityGroup(ctx context.Context, name string, opts ...CallOption) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("identity group name is empty")
	}
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, "identity/group/name/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

func mapToIdentityGroup(d map[string]interface{}) *IdentityGroup {
	return &IdentityGroup{
		ID:              asString(d["id"]),
		Name:            asString(d["name"]),
		Type:            asString(d["type"]),
		Policies:        asStringSlice(d["policies"]),
		MemberGroupIDs:  asStringSlice(d["member_group_ids"]),
		MemberEntityIDs: asStringSlice(d["member_entity_ids"]),
		Metadata:        asStringMap(d["metadata"]),
	}
}

// ---- Identity group aliases (identity/group-alias) ----

// WriteIdentityGroupAlias upserts a group-alias. Bao keys aliases by id,
// so on first create the body omits id and bao returns one; on update
// the body carries id and bao no-ops if (name, mount_accessor,
// canonical_id) all match. Empty id + duplicate (name, mount_accessor)
// returns 4xx — the controller calls FindIdentityGroupAlias first to
// stamp id on status.
func (c *sdkClient) WriteIdentityGroupAlias(ctx context.Context, spec IdentityGroupAliasSpec, opts ...CallOption) (*IdentityGroupAlias, error) {
	if strings.TrimSpace(spec.Name) == "" {
		return nil, errors.New("identity group alias name is empty")
	}
	if strings.TrimSpace(spec.MountAccessor) == "" {
		return nil, errors.New("identity group alias mount_accessor is empty")
	}
	body := map[string]interface{}{
		"name":           spec.Name,
		"mount_accessor": spec.MountAccessor,
	}
	if spec.ID != "" {
		body["id"] = spec.ID
	}
	if spec.CanonicalID != "" {
		body["canonical_id"] = spec.CanonicalID
	}
	resp, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "identity/group-alias", body)
	if err != nil {
		return nil, wrapStatus(err)
	}
	if resp == nil || resp.Data == nil {
		return &IdentityGroupAlias{
			ID:            spec.ID,
			Name:          spec.Name,
			MountAccessor: spec.MountAccessor,
			CanonicalID:   spec.CanonicalID,
		}, nil
	}
	return &IdentityGroupAlias{
		ID:            asString(resp.Data["id"]),
		Name:          firstNonEmpty(asString(resp.Data["name"]), spec.Name),
		MountAccessor: firstNonEmpty(asString(resp.Data["mount_accessor"]), spec.MountAccessor),
		CanonicalID:   firstNonEmpty(asString(resp.Data["canonical_id"]), spec.CanonicalID),
	}, nil
}

func (c *sdkClient) ReadIdentityGroupAliasByID(ctx context.Context, id string, opts ...CallOption) (*IdentityGroupAlias, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("identity group alias id is empty")
	}
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "identity/group-alias/id/"+id)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	return &IdentityGroupAlias{
		ID:            asString(resp.Data["id"]),
		Name:          asString(resp.Data["name"]),
		MountAccessor: asString(resp.Data["mount_accessor"]),
		CanonicalID:   asString(resp.Data["canonical_id"]),
	}, nil
}

// FindIdentityGroupAlias scans identity/group-alias/id LIST + per-id
// reads to locate an alias by (name, mount_accessor). Used on first
// reconcile to recover the bao id when a CR has been re-created or the
// operator has lost its status. Returns ErrNotFound when no match
// exists.
func (c *sdkClient) FindIdentityGroupAlias(ctx context.Context, name, mountAccessor string, opts ...CallOption) (*IdentityGroupAlias, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(mountAccessor) == "" {
		return nil, errors.New("identity group alias name or mount_accessor is empty")
	}
	resp, err := c.clientFor(opts).Logical().ListWithContext(ctx, "identity/group-alias/id")
	if err != nil {
		return nil, wrapStatus(err)
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	keyInfo, _ := resp.Data["key_info"].(map[string]interface{})
	keys := asStringSlice(resp.Data["keys"])
	for _, id := range keys {
		// Bao's LIST sometimes returns key_info inline; prefer it
		// to avoid an extra round-trip per id.
		if keyInfo != nil {
			if entry, ok := keyInfo[id].(map[string]interface{}); ok {
				if asString(entry["name"]) == name && asString(entry["mount_accessor"]) == mountAccessor {
					return &IdentityGroupAlias{
						ID:            id,
						Name:          asString(entry["name"]),
						MountAccessor: asString(entry["mount_accessor"]),
						CanonicalID:   asString(entry["canonical_id"]),
					}, nil
				}
				continue
			}
		}
		// Fallback: per-id read.
		alias, rerr := c.ReadIdentityGroupAliasByID(ctx, id, opts...)
		if rerr != nil {
			if errors.Is(rerr, ErrNotFound) {
				continue
			}
			return nil, rerr
		}
		if alias.Name == name && alias.MountAccessor == mountAccessor {
			return alias, nil
		}
	}
	return nil, ErrNotFound
}

func (c *sdkClient) DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...CallOption) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("identity group alias id is empty")
	}
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, "identity/group-alias/id/"+id)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- Identity OIDC roles (identity/oidc/role/<name>) ----

func (c *sdkClient) WriteIdentityTokenRole(ctx context.Context, name string, spec IdentityTokenRoleSpec, opts ...CallOption) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("identity token role name is empty")
	}
	if strings.TrimSpace(spec.Key) == "" {
		return errors.New("identity token role key is empty")
	}
	body := map[string]interface{}{
		"key": spec.Key,
	}
	if spec.Template != "" {
		body["template"] = spec.Template
	}
	if spec.ClientID != "" {
		body["client_id"] = spec.ClientID
	}
	if spec.TTL != "" {
		body["ttl"] = spec.TTL
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "identity/oidc/role/"+name, body)
	return wrapStatus(err)
}

func (c *sdkClient) ReadIdentityTokenRole(ctx context.Context, name string, opts ...CallOption) (*IdentityTokenRoleSpec, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("identity token role name is empty")
	}
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "identity/oidc/role/"+name)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	out := &IdentityTokenRoleSpec{
		Key:      asString(resp.Data["key"]),
		Template: asString(resp.Data["template"]),
		ClientID: asString(resp.Data["client_id"]),
	}
	// TTL comes back as int seconds; render as <n>s for spec round-trip
	// (matches the PKI role pattern).
	if p := asIntPtr(resp.Data["ttl"]); p != nil && *p > 0 {
		out.TTL = fmt.Sprintf("%ds", *p)
	} else {
		out.TTL = asString(resp.Data["ttl"])
	}
	return out, nil
}

func (c *sdkClient) DeleteIdentityTokenRole(ctx context.Context, name string, opts ...CallOption) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("identity token role name is empty")
	}
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, "identity/oidc/role/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- Cert auth mount-level config (auth/<mount>/config) ----

func (c *sdkClient) WriteCertAuthConfig(ctx context.Context, mount string, spec CertAuthConfigSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("cert auth mount is empty")
	}
	body := map[string]interface{}{}
	if spec.DisableBinding != nil {
		body["disable_binding"] = *spec.DisableBinding
	}
	if spec.EnableIdentityAliasMetadata != nil {
		body["enable_identity_alias_metadata"] = *spec.EnableIdentityAliasMetadata
	}
	if spec.OCSPCacheSize != nil {
		body["ocsp_cache_size"] = *spec.OCSPCacheSize
	}
	if spec.OCSPFailOpen != nil {
		body["ocsp_fail_open"] = *spec.OCSPFailOpen
	}
	if spec.OCSPQueryAllServers != nil {
		body["ocsp_query_all_servers"] = *spec.OCSPQueryAllServers
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "auth/"+mount+"/config", body)
	return wrapStatus(err)
}

func (c *sdkClient) ReadCertAuthConfig(ctx context.Context, mount string, opts ...CallOption) (*CertAuthConfigSpec, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "auth/"+mount+"/config")
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	d := resp.Data
	return &CertAuthConfigSpec{
		DisableBinding:              asBoolPtr(d["disable_binding"]),
		EnableIdentityAliasMetadata: asBoolPtr(d["enable_identity_alias_metadata"]),
		OCSPCacheSize:               asIntPtr(d["ocsp_cache_size"]),
		OCSPFailOpen:                asBoolPtr(d["ocsp_fail_open"]),
		OCSPQueryAllServers:         asBoolPtr(d["ocsp_query_all_servers"]),
	}, nil
}

// ---- Cert auth per-cert role (auth/<mount>/certs/<name>) ----

func (c *sdkClient) WriteCertAuthRole(ctx context.Context, mount, name string, spec CertAuthRoleSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" || strings.TrimSpace(name) == "" {
		return errors.New("cert auth mount or role name is empty")
	}
	if strings.TrimSpace(spec.Certificate) == "" {
		return errors.New("cert auth role certificate (CA bundle) is required")
	}
	body := map[string]interface{}{
		"certificate": spec.Certificate,
	}
	if spec.DisplayName != "" {
		body["display_name"] = spec.DisplayName
	}
	if len(spec.AllowedNames) > 0 {
		body["allowed_names"] = spec.AllowedNames
	}
	if len(spec.AllowedCommonNames) > 0 {
		body["allowed_common_names"] = spec.AllowedCommonNames
	}
	if len(spec.AllowedDNSSANs) > 0 {
		body["allowed_dns_sans"] = spec.AllowedDNSSANs
	}
	if len(spec.AllowedEmailSANs) > 0 {
		body["allowed_email_sans"] = spec.AllowedEmailSANs
	}
	if len(spec.AllowedURISANs) > 0 {
		body["allowed_uri_sans"] = spec.AllowedURISANs
	}
	if len(spec.AllowedOrganizations) > 0 {
		body["allowed_organizational_units"] = spec.AllowedOrganizations
	}
	if len(spec.RequiredExtensions) > 0 {
		body["required_extensions"] = spec.RequiredExtensions
	}
	if len(spec.TokenPolicies) > 0 {
		body["token_policies"] = spec.TokenPolicies
	}
	if spec.TokenTTL != "" {
		body["token_ttl"] = spec.TokenTTL
	}
	if spec.TokenMaxTTL != "" {
		body["token_max_ttl"] = spec.TokenMaxTTL
	}
	if spec.TokenPeriod != "" {
		body["token_period"] = spec.TokenPeriod
	}
	if len(spec.TokenBoundCIDRs) > 0 {
		body["token_bound_cidrs"] = spec.TokenBoundCIDRs
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "auth/"+mount+"/certs/"+name, body)
	return wrapStatus(err)
}

func (c *sdkClient) ReadCertAuthRole(ctx context.Context, mount, name string, opts ...CallOption) (*CertAuthRoleSpec, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "auth/"+mount+"/certs/"+name)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	d := resp.Data
	out := &CertAuthRoleSpec{
		Certificate:          asString(d["certificate"]),
		DisplayName:          asString(d["display_name"]),
		AllowedNames:         asStringSlice(d["allowed_names"]),
		AllowedCommonNames:   asStringSlice(d["allowed_common_names"]),
		AllowedDNSSANs:       asStringSlice(d["allowed_dns_sans"]),
		AllowedEmailSANs:     asStringSlice(d["allowed_email_sans"]),
		AllowedURISANs:       asStringSlice(d["allowed_uri_sans"]),
		AllowedOrganizations: asStringSlice(d["allowed_organizational_units"]),
		RequiredExtensions:   asStringSlice(d["required_extensions"]),
		TokenPolicies:        asStringSlice(d["token_policies"]),
		TokenBoundCIDRs:      asStringSlice(d["token_bound_cidrs"]),
	}
	out.TokenTTL = durationFromAny(d["token_ttl"])
	out.TokenMaxTTL = durationFromAny(d["token_max_ttl"])
	out.TokenPeriod = durationFromAny(d["token_period"])
	return out, nil
}

func (c *sdkClient) DeleteCertAuthRole(ctx context.Context, mount, name string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, "auth/"+mount+"/certs/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// ---- JWT/OIDC auth (auth/<mount>/config + auth/<mount>/role/<name>) ----

func (c *sdkClient) WriteJWTOIDCConfig(ctx context.Context, mount string, spec JWTOIDCConfigSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return errors.New("jwt/oidc auth mount is empty")
	}
	body := map[string]interface{}{}
	if spec.OIDCDiscoveryURL != "" {
		body["oidc_discovery_url"] = spec.OIDCDiscoveryURL
	}
	if spec.OIDCDiscoveryCAPEM != "" {
		body["oidc_discovery_ca_pem"] = spec.OIDCDiscoveryCAPEM
	}
	if spec.OIDCClientID != "" {
		body["oidc_client_id"] = spec.OIDCClientID
	}
	if spec.OIDCClientSecret != "" {
		body["oidc_client_secret"] = spec.OIDCClientSecret
	}
	if spec.OIDCResponseMode != "" {
		body["oidc_response_mode"] = spec.OIDCResponseMode
	}
	if len(spec.OIDCResponseTypes) > 0 {
		body["oidc_response_types"] = spec.OIDCResponseTypes
	}
	if spec.JWKsURL != "" {
		body["jwks_url"] = spec.JWKsURL
	}
	if spec.JWKsCAPEM != "" {
		body["jwks_ca_pem"] = spec.JWKsCAPEM
	}
	if len(spec.JWTValidationPubkeys) > 0 {
		body["jwt_validation_pubkeys"] = spec.JWTValidationPubkeys
	}
	if len(spec.JWTSupportedAlgs) > 0 {
		body["jwt_supported_algs"] = spec.JWTSupportedAlgs
	}
	if spec.BoundIssuer != "" {
		body["bound_issuer"] = spec.BoundIssuer
	}
	if spec.DefaultRole != "" {
		body["default_role"] = spec.DefaultRole
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "auth/"+mount+"/config", body)
	return wrapStatus(err)
}

func (c *sdkClient) ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...CallOption) (*JWTOIDCConfigSpec, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "auth/"+mount+"/config")
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	d := resp.Data
	return &JWTOIDCConfigSpec{
		OIDCDiscoveryURL:     asString(d["oidc_discovery_url"]),
		OIDCDiscoveryCAPEM:   asString(d["oidc_discovery_ca_pem"]),
		OIDCClientID:         asString(d["oidc_client_id"]),
		OIDCClientSecret:     asString(d["oidc_client_secret"]),
		OIDCResponseMode:     asString(d["oidc_response_mode"]),
		OIDCResponseTypes:    asStringSlice(d["oidc_response_types"]),
		JWKsURL:              asString(d["jwks_url"]),
		JWKsCAPEM:            asString(d["jwks_ca_pem"]),
		JWTValidationPubkeys: asStringSlice(d["jwt_validation_pubkeys"]),
		JWTSupportedAlgs:     asStringSlice(d["jwt_supported_algs"]),
		BoundIssuer:          asString(d["bound_issuer"]),
		DefaultRole:          asString(d["default_role"]),
	}, nil
}

func (c *sdkClient) WriteJWTOIDCRole(ctx context.Context, mount, name string, spec JWTOIDCRoleSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" || strings.TrimSpace(name) == "" {
		return errors.New("jwt/oidc auth mount or role name is empty")
	}
	if strings.TrimSpace(spec.RoleType) == "" {
		return errors.New("jwt/oidc role role_type is required (\"jwt\" or \"oidc\")")
	}
	body := map[string]interface{}{
		"role_type": spec.RoleType,
	}
	if spec.UserClaim != "" {
		body["user_claim"] = spec.UserClaim
	}
	if spec.UserClaimJSONPointer != nil {
		body["user_claim_json_pointer"] = *spec.UserClaimJSONPointer
	}
	if len(spec.BoundAudiences) > 0 {
		body["bound_audiences"] = spec.BoundAudiences
	}
	if spec.BoundSubject != "" {
		body["bound_subject"] = spec.BoundSubject
	}
	if spec.BoundClaimsType != "" {
		body["bound_claims_type"] = spec.BoundClaimsType
	}
	if len(spec.BoundClaims) > 0 {
		body["bound_claims"] = spec.BoundClaims
	}
	if spec.GroupsClaim != "" {
		body["groups_claim"] = spec.GroupsClaim
	}
	if len(spec.ClaimMappings) > 0 {
		body["claim_mappings"] = spec.ClaimMappings
	}
	if len(spec.OIDCScopes) > 0 {
		body["oidc_scopes"] = spec.OIDCScopes
	}
	if len(spec.AllowedRedirectURIs) > 0 {
		body["allowed_redirect_uris"] = spec.AllowedRedirectURIs
	}
	if spec.VerboseOIDCLogging != nil {
		body["verbose_oidc_logging"] = *spec.VerboseOIDCLogging
	}
	if len(spec.TokenPolicies) > 0 {
		body["token_policies"] = spec.TokenPolicies
	}
	if spec.TokenTTL != "" {
		body["token_ttl"] = spec.TokenTTL
	}
	if spec.TokenMaxTTL != "" {
		body["token_max_ttl"] = spec.TokenMaxTTL
	}
	if len(spec.TokenBoundCIDRs) > 0 {
		body["token_bound_cidrs"] = spec.TokenBoundCIDRs
	}
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, "auth/"+mount+"/role/"+name, body)
	return wrapStatus(err)
}

func (c *sdkClient) ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...CallOption) (*JWTOIDCRoleSpec, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, "auth/"+mount+"/role/"+name)
	if err != nil {
		wrapped := wrapStatus(err)
		var se *StatusError
		if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, wrapped
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	d := resp.Data
	out := &JWTOIDCRoleSpec{
		RoleType:             asString(d["role_type"]),
		UserClaim:            asString(d["user_claim"]),
		UserClaimJSONPointer: asBoolPtr(d["user_claim_json_pointer"]),
		BoundAudiences:       asStringSlice(d["bound_audiences"]),
		BoundSubject:         asString(d["bound_subject"]),
		BoundClaimsType:      asString(d["bound_claims_type"]),
		GroupsClaim:          asString(d["groups_claim"]),
		OIDCScopes:           asStringSlice(d["oidc_scopes"]),
		AllowedRedirectURIs:  asStringSlice(d["allowed_redirect_uris"]),
		VerboseOIDCLogging:   asBoolPtr(d["verbose_oidc_logging"]),
		TokenPolicies:        asStringSlice(d["token_policies"]),
		TokenBoundCIDRs:      asStringSlice(d["token_bound_cidrs"]),
	}
	if cm, ok := d["bound_claims"].(map[string]interface{}); ok {
		out.BoundClaims = cm
	}
	if cm, ok := d["claim_mappings"].(map[string]interface{}); ok {
		out.ClaimMappings = make(map[string]string, len(cm))
		for k, v := range cm {
			if s, ok := v.(string); ok {
				out.ClaimMappings[k] = s
			}
		}
	}
	out.TokenTTL = durationFromAny(d["token_ttl"])
	out.TokenMaxTTL = durationFromAny(d["token_max_ttl"])
	return out, nil
}

func (c *sdkClient) DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, "auth/"+mount+"/role/"+name)
	if err == nil {
		return nil
	}
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return nil
	}
	return wrapped
}

// durationFromAny renders a bao TTL response (which can be int seconds
// or a string) as a stable <n>s string the spec round-trips against.
// Mirrors the PKI role pattern.
func durationFromAny(v any) string {
	if p := asIntPtr(v); p != nil {
		if *p == 0 {
			return ""
		}
		return fmt.Sprintf("%ds", *p)
	}
	return asString(v)
}

// asStringMap coerces a map-shaped bao response value into
// map[string]string. Bao serializes JSON objects as
// map[string]interface{}; values that are not strings are dropped
// rather than coerced — the controller expects string-typed metadata
// only.
func asStringMap(v any) map[string]string {
	if v == nil {
		return nil
	}
	switch m := v.(type) {
	case map[string]string:
		out := make(map[string]string, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out
	case map[string]interface{}:
		out := make(map[string]string, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
		return out
	}
	return nil
}

func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// asIntPtr coerces a vault/api response value into *int. vault/api returns
// JSON numbers as json.Number; the helper also accepts native int / int64 /
// float64 because httptest-based unit tests construct response bodies with
// plain Go literals. Returns nil on missing or unrecognized shape so the
// caller can treat "not present" identically to "not parseable".
func asIntPtr(v any) *int {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			n := int(i)
			return &n
		}
	case int:
		return &x
	case int64:
		n := int(x)
		return &n
	case float64:
		n := int(x)
		return &n
	case string:
		if i, err := strconv.Atoi(x); err == nil {
			return &i
		}
	}
	return nil
}
