package connection

import (
	"context"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// ctxClient is a baoclient.Client that routes every call through the
// per-connection client resolved for the current reconcile and injected into
// the context by the shared reconcile engine (resource.WithBaoClient). This
// is how the primitives adopt multi-connection without touching any of their
// handler closures: main.go passes WrapClient as the single bao injected
// into every constructor, and each call reads the ctx-resolved client (which
// always exists in production because the engine resolves before handlers
// run). Tests construct handlers with the real fake bao directly, so they
// never go through the wrapper.
type ctxClient struct {
	fallback baoclient.Client
}

// WrapClient returns a baoclient.Client that delegates to the per-reconcile
// client in ctx, falling back to fallback when ctx carries none (test struct
// literals / un-migrated primitives).
func WrapClient(fallback baoclient.Client) baoclient.Client {
	return &ctxClient{fallback: fallback}
}

func (c *ctxClient) resolve(ctx context.Context) baoclient.Client {
	if b := resource.BaoClientFromContext(ctx); b != nil {
		return b
	}
	return c.fallback
}

func (c *ctxClient) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return c.resolve(ctx).CheckKVv2Mount(ctx, mount, opts...)
}

func (c *ctxClient) TokenLookupSelf(ctx context.Context, opts ...baoclient.CallOption) (*baoclient.TokenInfo, error) {
	return c.resolve(ctx).TokenLookupSelf(ctx, opts...)
}

func (c *ctxClient) EnableSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).EnableSecretEngine(ctx, mount, spec, opts...)
}

func (c *ctxClient) TuneSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).TuneSecretEngine(ctx, mount, spec, opts...)
}

func (c *ctxClient) GetSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.SecretEngineMount, error) {
	return c.resolve(ctx).GetSecretEngineMount(ctx, mount, opts...)
}

func (c *ctxClient) DisableSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DisableSecretEngineMount(ctx, mount, opts...)
}

func (c *ctxClient) EnableAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).EnableAuthMethod(ctx, mount, spec, opts...)
}

func (c *ctxClient) TuneAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).TuneAuthMethod(ctx, mount, spec, opts...)
}

func (c *ctxClient) GetAuthMethod(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.AuthMethodMount, error) {
	return c.resolve(ctx).GetAuthMethod(ctx, mount, opts...)
}

func (c *ctxClient) DisableAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DisableAuthMount(ctx, mount, opts...)
}

func (c *ctxClient) CreateNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).CreateNamespace(ctx, name, opts...)
}

func (c *ctxClient) GetNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.Namespace, error) {
	return c.resolve(ctx).GetNamespace(ctx, name, opts...)
}

func (c *ctxClient) DeleteNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteNamespace(ctx, name, opts...)
}

func (c *ctxClient) UpsertPolicy(ctx context.Context, name, rules string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).UpsertPolicy(ctx, name, rules, opts...)
}

func (c *ctxClient) GetPolicy(ctx context.Context, name string, opts ...baoclient.CallOption) (string, error) {
	return c.resolve(ctx).GetPolicy(ctx, name, opts...)
}

func (c *ctxClient) DeletePolicy(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeletePolicy(ctx, name, opts...)
}

func (c *ctxClient) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec baoclient.K8sRoleSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).UpsertK8sRole(ctx, authMount, roleName, spec, opts...)
}

func (c *ctxClient) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return c.resolve(ctx).GetK8sRole(ctx, authMount, roleName, opts...)
}

func (c *ctxClient) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteK8sRole(ctx, authMount, roleName, opts...)
}

func (c *ctxClient) GenerateRootPKI(ctx context.Context, mount string, in baoclient.PKIRootGenerateInput, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return c.resolve(ctx).GenerateRootPKI(ctx, mount, in, opts...)
}

func (c *ctxClient) ReadPKICA(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return c.resolve(ctx).ReadPKICA(ctx, mount, opts...)
}

func (c *ctxClient) WritePKIURLs(ctx context.Context, mount string, in baoclient.PKIURLsInput, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WritePKIURLs(ctx, mount, in, opts...)
}

func (c *ctxClient) ReadPKIURLs(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	return c.resolve(ctx).ReadPKIURLs(ctx, mount, opts...)
}

func (c *ctxClient) GenerateIntermediateCSR(ctx context.Context, mount string, in baoclient.PKIIntermediateGenerateInput, opts ...baoclient.CallOption) (string, error) {
	return c.resolve(ctx).GenerateIntermediateCSR(ctx, mount, in, opts...)
}

func (c *ctxClient) SignIntermediate(ctx context.Context, rootMount, csr string, in baoclient.PKISignIntermediateInput, opts ...baoclient.CallOption) (string, error) {
	return c.resolve(ctx).SignIntermediate(ctx, rootMount, csr, in, opts...)
}

func (c *ctxClient) SetSignedIntermediate(ctx context.Context, mount, certificate string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).SetSignedIntermediate(ctx, mount, certificate, opts...)
}

func (c *ctxClient) ListPKIKeys(ctx context.Context, mount string, opts ...baoclient.CallOption) ([]string, error) {
	return c.resolve(ctx).ListPKIKeys(ctx, mount, opts...)
}

func (c *ctxClient) WritePKIRole(ctx context.Context, mount, name string, spec baoclient.PKIRoleSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WritePKIRole(ctx, mount, name, spec, opts...)
}

func (c *ctxClient) ReadPKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	return c.resolve(ctx).ReadPKIRole(ctx, mount, name, opts...)
}

func (c *ctxClient) DeletePKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeletePKIRole(ctx, mount, name, opts...)
}

func (c *ctxClient) WriteDatabaseConnection(ctx context.Context, mount, name string, spec baoclient.DatabaseConnectionConfig, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteDatabaseConnection(ctx, mount, name, spec, opts...)
}

func (c *ctxClient) ReadDatabaseConnection(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.DatabaseConnectionConfig, error) {
	return c.resolve(ctx).ReadDatabaseConnection(ctx, mount, name, opts...)
}

func (c *ctxClient) DeleteDatabaseConnection(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteDatabaseConnection(ctx, mount, name, opts...)
}

func (c *ctxClient) WriteDatabaseRole(ctx context.Context, mount, name string, spec baoclient.DatabaseRoleSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteDatabaseRole(ctx, mount, name, spec, opts...)
}

func (c *ctxClient) ReadDatabaseRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.DatabaseRoleSpec, error) {
	return c.resolve(ctx).ReadDatabaseRole(ctx, mount, name, opts...)
}

func (c *ctxClient) DeleteDatabaseRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteDatabaseRole(ctx, mount, name, opts...)
}

func (c *ctxClient) WriteIdentityGroup(ctx context.Context, spec baoclient.IdentityGroupSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return c.resolve(ctx).WriteIdentityGroup(ctx, spec, opts...)
}

func (c *ctxClient) ReadIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return c.resolve(ctx).ReadIdentityGroup(ctx, name, opts...)
}

func (c *ctxClient) DeleteIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteIdentityGroup(ctx, name, opts...)
}

func (c *ctxClient) WriteIdentityGroupAlias(ctx context.Context, spec baoclient.IdentityGroupAliasSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return c.resolve(ctx).WriteIdentityGroupAlias(ctx, spec, opts...)
}

func (c *ctxClient) ReadIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return c.resolve(ctx).ReadIdentityGroupAliasByID(ctx, id, opts...)
}

func (c *ctxClient) FindIdentityGroupAlias(ctx context.Context, name, mountAccessor string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return c.resolve(ctx).FindIdentityGroupAlias(ctx, name, mountAccessor, opts...)
}

func (c *ctxClient) DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteIdentityGroupAliasByID(ctx, id, opts...)
}

func (c *ctxClient) WriteIdentityTokenRole(ctx context.Context, name string, spec baoclient.IdentityTokenRoleSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteIdentityTokenRole(ctx, name, spec, opts...)
}

func (c *ctxClient) ReadIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	return c.resolve(ctx).ReadIdentityTokenRole(ctx, name, opts...)
}

func (c *ctxClient) DeleteIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteIdentityTokenRole(ctx, name, opts...)
}

func (c *ctxClient) WriteCertAuthConfig(ctx context.Context, mount string, spec baoclient.CertAuthConfigSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteCertAuthConfig(ctx, mount, spec, opts...)
}

func (c *ctxClient) ReadCertAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.CertAuthConfigSpec, error) {
	return c.resolve(ctx).ReadCertAuthConfig(ctx, mount, opts...)
}

func (c *ctxClient) WriteCertAuthRole(ctx context.Context, mount, name string, spec baoclient.CertAuthRoleSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteCertAuthRole(ctx, mount, name, spec, opts...)
}

func (c *ctxClient) ReadCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.CertAuthRoleSpec, error) {
	return c.resolve(ctx).ReadCertAuthRole(ctx, mount, name, opts...)
}

func (c *ctxClient) DeleteCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteCertAuthRole(ctx, mount, name, opts...)
}

func (c *ctxClient) WriteJWTOIDCConfig(ctx context.Context, mount string, spec baoclient.JWTOIDCConfigSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteJWTOIDCConfig(ctx, mount, spec, opts...)
}

func (c *ctxClient) ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	return c.resolve(ctx).ReadJWTOIDCConfig(ctx, mount, opts...)
}

func (c *ctxClient) WriteK8sAuthConfig(ctx context.Context, mount string, spec baoclient.K8sAuthConfigSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteK8sAuthConfig(ctx, mount, spec, opts...)
}

func (c *ctxClient) ReadK8sAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
	return c.resolve(ctx).ReadK8sAuthConfig(ctx, mount, opts...)
}

func (c *ctxClient) WriteJWTOIDCRole(ctx context.Context, mount, name string, spec baoclient.JWTOIDCRoleSpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteJWTOIDCRole(ctx, mount, name, spec, opts...)
}

func (c *ctxClient) ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return c.resolve(ctx).ReadJWTOIDCRole(ctx, mount, name, opts...)
}

func (c *ctxClient) DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteJWTOIDCRole(ctx, mount, name, opts...)
}

func (c *ctxClient) WriteTransitKey(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).WriteTransitKey(ctx, mount, name, spec, opts...)
}

func (c *ctxClient) ReadTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.TransitKeyInfo, error) {
	return c.resolve(ctx).ReadTransitKey(ctx, mount, name, opts...)
}

func (c *ctxClient) UpdateTransitKeyConfig(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).UpdateTransitKeyConfig(ctx, mount, name, spec, opts...)
}

func (c *ctxClient) DeleteTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteTransitKey(ctx, mount, name, opts...)
}

func (c *ctxClient) WriteKVSecret(ctx context.Context, mount, path string, data map[string]string, opts ...baoclient.CallOption) (int, error) {
	return c.resolve(ctx).WriteKVSecret(ctx, mount, path, data, opts...)
}

func (c *ctxClient) ReadKVSecret(ctx context.Context, mount, path string, opts ...baoclient.CallOption) (*baoclient.KVSecret, error) {
	return c.resolve(ctx).ReadKVSecret(ctx, mount, path, opts...)
}

func (c *ctxClient) DeleteKVSecret(ctx context.Context, mount, path string, opts ...baoclient.CallOption) error {
	return c.resolve(ctx).DeleteKVSecret(ctx, mount, path, opts...)
}
