package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// redactRe matches a "user:password@" authority prefix of a connection URL
// (with or without a scheme — MySQL templates are bare user:pass@host) and
// replaces the password with "***". The password run is bounded by
// [^@/:\s]* so it stops at the '@', a path '/', a further ':' (IPv6/port in
// a quoted host is rare here), or whitespace. Placeholder and real
// credentials alike are normalised, and a "user@host" form with no password
// is left untouched.
var redactRe = regexp.MustCompile(`([^@/:\s]+):([^@/:\s]*)@`)

// DatabaseConnectionConfig mirrors the write/read shape of a database
// secret-engine connection config at <mount>/config/<name>.
//
// Username/Password are resolved by the controller from a k8s Secret and
// supplied to the write call so they can be interpolated into the
// connection_url template's {{username}}/{{password}} placeholders. They
// are NOT returned by ReadDatabaseConnection (bao redacts the password and
// the CR never echoes it), so the read shape carries the structural fields
// only; the CR-side drift comparator masks the connection_url's userinfo
// before comparing.
type DatabaseConnectionConfig struct {
	// PluginName is the database plugin serving this connection
	// (e.g. "mysql-database-plugin", "postgresql-database-plugin").
	PluginName string
	// ConnectionURL is the plugin connection template, typically with
	// {{username}}:{{password}} placeholders (e.g.
	// "{{username}}:{{password}}@tcp(db-host:3306)/").
	ConnectionURL string
	// AllowedRoles is the set of roles permitted to use this connection.
	AllowedRoles []string
	// VerifyConnection pings the database on write.
	VerifyConnection bool
	// MaxOpenConnections / MaxIdleConnections bound the pool.
	MaxOpenConnections int
	MaxIdleConnections int
	// MaxConnectionLifetime is a bao duration ("5m", "300s").
	MaxConnectionLifetime string
	// TLSServerName overrides the TLS server name validation hostname.
	TLSServerName string
	// TLSSkipVerify disables TLS verification for the connection.
	TLSSkipVerify bool
	// PasswordPolicy names a password policy applied to generated
	// credentials' passwords. Empty = default.
	PasswordPolicy string

	// Username/Password are the connection credential pair; write-only.
	Username string
	Password string
}

// DatabaseRoleSpec mirrors the write/read shape of a database static role
// at <mount>/roles/<name>.
type DatabaseRoleSpec struct {
	// Database is the connection name (db_name) this role targets.
	Database string
	// CreationStatements are the SQL statements executing on cred create.
	CreationStatements []string
	// RotationStatements rotate the generated credential (dynamic roles).
	RotationStatements []string
	// RevocationStatements run on lease revoke.
	RevocationStatements []string
	// RollbackStatements run when creation fails partway (cleanup).
	RollbackStatements []string
	// CredentialType for these plugins is "password".
	CredentialType string
	// DefaultTTL is the lease TTL of minted credentials (bao duration).
	DefaultTTL string
	// MaxTTL is the upper bound on minted credential TTL.
	MaxTTL string
}

// WriteDatabaseConnection upserts a connection config at
// /<mount>/config/<name>. Idempotent on path.
func (c *sdkClient) WriteDatabaseConnection(ctx context.Context, mount, name string, spec DatabaseConnectionConfig, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" || name == "" {
		return errors.New("mount or connection name empty")
	}
	if strings.TrimSpace(spec.PluginName) == "" {
		return errors.New("connection plugin_name must not be empty")
	}
	body := databaseConnectionToMap(spec)
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, mount+"/config/"+name, body)
	return wrapStatus(err)
}

// ReadDatabaseConnection fetches the connection config. Returns
// ErrNotFound on 404 or a successful read with no data.
func (c *sdkClient) ReadDatabaseConnection(ctx context.Context, mount, name string, opts ...CallOption) (*DatabaseConnectionConfig, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, mount+"/config/"+name)
	if err != nil {
		return nil, classifyReadErr(err)
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	return mapToDatabaseConnection(resp.Data), nil
}

// DeleteDatabaseConnection removes a connection. Idempotent on 404.
func (c *sdkClient) DeleteDatabaseConnection(ctx context.Context, mount, name string, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	_, err := c.clientFor(opts).Logical().DeleteWithContext(ctx, mount+"/config/"+name)
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

// WriteDatabaseRole upserts a static role at /<mount>/roles/<name>.
func (c *sdkClient) WriteDatabaseRole(ctx context.Context, mount, name string, spec DatabaseRoleSpec, opts ...CallOption) error {
	mount = strings.Trim(mount, "/")
	if mount == "" || name == "" {
		return errors.New("mount or role name empty")
	}
	body := databaseRoleToMap(spec)
	_, err := c.clientFor(opts).Logical().WriteWithContext(ctx, mount+"/roles/"+name, body)
	return wrapStatus(err)
}

// ReadDatabaseRole fetches a role. Returns ErrNotFound on 404 or empty data.
func (c *sdkClient) ReadDatabaseRole(ctx context.Context, mount, name string, opts ...CallOption) (*DatabaseRoleSpec, error) {
	mount = strings.Trim(mount, "/")
	resp, err := c.clientFor(opts).Logical().ReadWithContext(ctx, mount+"/roles/"+name)
	if err != nil {
		return nil, classifyReadErr(err)
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrNotFound
	}
	return mapToDatabaseRole(resp.Data), nil
}

// DeleteDatabaseRole removes a role. Idempotent on 404.
func (c *sdkClient) DeleteDatabaseRole(ctx context.Context, mount, name string, opts ...CallOption) error {
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

// classifyReadErr maps a read error to the local contract, coalescing a
// 404 into the bare ErrNotFound sentinel (mirrors ReadPKIRole).
func classifyReadErr(err error) error {
	wrapped := wrapStatus(err)
	var se *StatusError
	if errors.As(wrapped, &se) && se.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	return wrapped
}

// databaseConnectionToMap builds the write body. The credential pair and
// TLS/pool fields are only emitted when non-zero so bao defaults stay in
// effect otherwise. connection_url is always emitted (required).
func databaseConnectionToMap(s DatabaseConnectionConfig) map[string]interface{} {
	body := map[string]interface{}{
		"plugin_name":       s.PluginName,
		"connection_url":    s.ConnectionURL,
		"verify_connection": s.VerifyConnection,
	}
	if s.Username != "" {
		body["username"] = s.Username
	}
	if s.Password != "" {
		body["password"] = s.Password
	}
	if len(s.AllowedRoles) > 0 {
		body["allowed_roles"] = s.AllowedRoles
	}
	if s.MaxOpenConnections != 0 {
		body["max_open_connections"] = s.MaxOpenConnections
	}
	if s.MaxIdleConnections != 0 {
		body["max_idle_connections"] = s.MaxIdleConnections
	}
	if s.MaxConnectionLifetime != "" {
		body["max_connection_lifetime"] = s.MaxConnectionLifetime
	}
	if s.TLSServerName != "" {
		body["tls_server_name"] = s.TLSServerName
	}
	if s.TLSSkipVerify {
		body["tls_skip_verify"] = true
	}
	if s.PasswordPolicy != "" {
		body["password_policy"] = s.PasswordPolicy
	}
	return body
}

// mapToDatabaseConnection reverses databaseConnectionToMap for drift
// comparison. Bao echoes pool/TLS fields and the connection_url. Duration
// fields come back as integer seconds; formatted as "<n>s" to match bao
// duration strings. Password is excluded (not returned by the read).
func mapToDatabaseConnection(d map[string]interface{}) *DatabaseConnectionConfig {
	durStr := func(v any) string {
		if p := asIntPtr(v); p != nil {
			if *p == 0 {
				return ""
			}
			return fmt.Sprintf("%ds", *p)
		}
		return asString(v)
	}
	derefBool := func(v any) bool {
		p := asBoolPtr(v)
		return p != nil && *p
	}
	derefInt := func(v any) int {
		p := asIntPtr(v)
		if p == nil {
			return 0
		}
		return *p
	}
	return &DatabaseConnectionConfig{
		PluginName:            asString(d["plugin_name"]),
		ConnectionURL:         asString(d["connection_url"]),
		AllowedRoles:          asStringSlice(d["allowed_roles"]),
		VerifyConnection:      derefBool(d["verify_connection"]),
		MaxOpenConnections:    derefInt(d["max_open_connections"]),
		MaxIdleConnections:    derefInt(d["max_idle_connections"]),
		MaxConnectionLifetime: durStr(d["max_connection_lifetime"]),
		TLSServerName:         asString(d["tls_server_name"]),
		TLSSkipVerify:         derefBool(d["tls_skip_verify"]),
		PasswordPolicy:        asString(d["password_policy"]),
	}
}

// databaseRoleToMap builds the role write body (db_name and the SQL
// statement lists).
func databaseRoleToMap(s DatabaseRoleSpec) map[string]interface{} {
	body := map[string]interface{}{
		"db_name": s.Database,
	}
	if s.Database == "" {
		delete(body, "db_name")
	}
	if len(s.CreationStatements) > 0 {
		body["creation_statements"] = s.CreationStatements
	}
	if len(s.RotationStatements) > 0 {
		body["rotation_statements"] = s.RotationStatements
	}
	if len(s.RevocationStatements) > 0 {
		body["revocation_statements"] = s.RevocationStatements
	}
	if len(s.RollbackStatements) > 0 {
		body["rollback_statements"] = s.RollbackStatements
	}
	if s.CredentialType != "" {
		body["credential_type"] = s.CredentialType
	}
	if s.DefaultTTL != "" {
		body["default_ttl"] = s.DefaultTTL
	}
	if s.MaxTTL != "" {
		body["max_ttl"] = s.MaxTTL
	}
	return body
}

// mapToDatabaseRole reverses databaseRoleToMap for drift comparison. TTL
// fields echo back as integer seconds; formatted as "<n>s".
func mapToDatabaseRole(d map[string]interface{}) *DatabaseRoleSpec {
	durStr := func(v any) string {
		if p := asIntPtr(v); p != nil {
			if *p == 0 {
				return ""
			}
			return fmt.Sprintf("%ds", *p)
		}
		return asString(v)
	}
	return &DatabaseRoleSpec{
		Database:             asString(d["db_name"]),
		CreationStatements:   asStringSlice(d["creation_statements"]),
		RotationStatements:   asStringSlice(d["rotation_statements"]),
		RevocationStatements: asStringSlice(d["revocation_statements"]),
		RollbackStatements:   asStringSlice(d["rollback_statements"]),
		CredentialType:       asString(d["credential_type"]),
		DefaultTTL:           durStr(d["default_ttl"]),
		MaxTTL:               durStr(d["max_ttl"]),
	}
}

// MaskConnectionURL redacts the userinfo (username:password) portion of a
// connection URL template, leaving host/path for structural comparison.
// Used by the CR drift comparators so a credential rotation (which changes
// only the password) never looks like config drift.
//
// The regexp matches the <userinfo>:<password> run preceding the '@' of a
// URL authority and replaces the password with "***". Placeholder forms
// ("{{username}}:{{password}}@") and real credentials alike are normalised
// so the comparison ignores the credential pair entirely.
func MaskConnectionURL(raw string) string {
	if raw == "" {
		return ""
	}
	// Match "user:pass@" where pass may contain no '/' or whitespace,
	// and replace with "user:***@". If there is no colon password the
	// marker (user@) is left alone.
	redacted := redactRe.ReplaceAllString(raw, "$1:***@")
	return redacted
}
