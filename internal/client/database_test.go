package client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteDatabaseConnection_PostsBody(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	err := c.WriteDatabaseConnection(context.Background(), "database", "app-db", DatabaseConnectionConfig{
		PluginName:            "mysql-database-plugin",
		ConnectionURL:         "{{username}}:{{password}}@tcp(db.example.com:3306)/",
		Username:              "admin",
		Password:              "s3cret",
		AllowedRoles:          []string{"app"},
		VerifyConnection:      true,
		MaxIdleConnections:    2,
		MaxOpenConnections:    5,
		MaxConnectionLifetime: "300s",
		TLSServerName:         "db.example.com",
	})
	require.NoError(t, err)
	require.Equal(t, "/v1/database/config/app-db", gotPath)
	require.Equal(t, "mysql-database-plugin", gotBody["plugin_name"])
	require.Equal(t, "admin", gotBody["username"])
	require.Equal(t, "s3cret", gotBody["password"])
	require.Equal(t, []any{"app"}, gotBody["allowed_roles"])
	require.Equal(t, true, gotBody["verify_connection"])
	// JSON numbers decode as float64 at the map boundary.
	require.Equal(t, float64(5), gotBody["max_open_connections"])
	require.Equal(t, "300s", gotBody["max_connection_lifetime"])
	// Zero-valued optional fields must be elided so bao keeps defaults.
	_, hasSkip := gotBody["tls_skip_verify"]
	require.False(t, hasSkip, "zero-valued fields elided from write body")
	_, hasPolicy := gotBody["password_policy"]
	require.False(t, hasPolicy, "empty password_policy elided")
}

func TestWriteDatabaseConnection_RejectsEmptyMountOrName(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	require.Error(t, c.WriteDatabaseConnection(context.Background(), "", "x", DatabaseConnectionConfig{PluginName: "mysql-database-plugin", ConnectionURL: "u"}), "empty mount rejected")
	require.Error(t, c.WriteDatabaseConnection(context.Background(), "database", "", DatabaseConnectionConfig{PluginName: "mysql-database-plugin", ConnectionURL: "u"}), "empty name rejected")
	require.Error(t, c.WriteDatabaseConnection(context.Background(), "database", "x", DatabaseConnectionConfig{ConnectionURL: "u"}), "empty plugin rejected")
}

func TestReadDatabaseConnection_DecodesAndNormalizes(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/database/config/app-db", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"plugin_name":             "mysql-database-plugin",
				"connection_url":          "{{username}}:{{password}}@tcp(db.example.com:3306)/",
				"allowed_roles":           []any{"app"},
				"verify_connection":       true,
				"max_open_connections":    5,
				"max_idle_connections":    2,
				"max_connection_lifetime": 300, // bao returns int seconds
				"tls_server_name":         "db.example.com",
			},
		})
	})
	cfg, err := c.ReadDatabaseConnection(context.Background(), "database", "app-db")
	require.NoError(t, err)
	require.Equal(t, "mysql-database-plugin", cfg.PluginName)
	require.Equal(t, []string{"app"}, cfg.AllowedRoles)
	require.True(t, cfg.VerifyConnection)
	require.Equal(t, 5, cfg.MaxOpenConnections)
	require.Equal(t, 2, cfg.MaxIdleConnections)
	require.Equal(t, "300s", cfg.MaxConnectionLifetime,
		"int seconds normalized to <n>s string for spec-shape round-trip")
	require.Equal(t, "db.example.com", cfg.TLSServerName)
	require.Empty(t, cfg.Username, "credentials are never echoed by the read")
	require.Empty(t, cfg.Password, "credentials are never echoed by the read")
}

func TestReadDatabaseConnection_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadDatabaseConnection(context.Background(), "database", "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteDatabaseConnection_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/database/config/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteDatabaseConnection(context.Background(), "database", "missing"),
		"404 = already gone, treated as idempotent success")
}

func TestWriteDatabaseRole_PostsBody(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	err := c.WriteDatabaseRole(context.Background(), "database", "app", DatabaseRoleSpec{
		Database:             "app-db",
		CreationStatements:   []string{"CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'", "GRANT SELECT ON app.* TO '{{name}}'@'%'"},
		RevocationStatements: []string{"DROP USER IF EXISTS '{{name}}'@'%'"},
		CredentialType:       "password",
		DefaultTTL:           "3600s",
		MaxTTL:               "86400s",
	})
	require.NoError(t, err)
	require.Equal(t, "/v1/database/roles/app", gotPath)
	require.Equal(t, "app-db", gotBody["db_name"])
	require.Equal(t, []any{"CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'", "GRANT SELECT ON app.* TO '{{name}}'@'%'"}, gotBody["creation_statements"])
	require.Equal(t, []any{"DROP USER IF EXISTS '{{name}}'@'%'"}, gotBody["revocation_statements"])
	require.Equal(t, "password", gotBody["credential_type"])
	require.Equal(t, "3600s", gotBody["default_ttl"])
}

func TestReadDatabaseRole_DecodesAndNormalizesTTL(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/database/roles/app", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"db_name":               "app-db",
				"creation_statements":   []any{"CREATE USER '{{name}}'@'%'", "GRANT ALL ON app.* TO '{{name}}'@'%'"},
				"revocation_statements": []any{"DROP USER IF EXISTS '{{name}}'@'%'"},
				"rollback_statements":   []any{"DROP USER IF EXISTS '{{name}}'@'%'"},
				"credential_type":       "password",
				"default_ttl":           3600,
				"max_ttl":               86400,
			},
		})
	})
	role, err := c.ReadDatabaseRole(context.Background(), "database", "app")
	require.NoError(t, err)
	require.Equal(t, "app-db", role.Database)
	require.Len(t, role.CreationStatements, 2)
	require.Equal(t, []string{"DROP USER IF EXISTS '{{name}}'@'%'"}, role.RevocationStatements)
	require.Equal(t, "password", role.CredentialType)
	require.Equal(t, "3600s", role.DefaultTTL, "int seconds normalized to <n>s string")
	require.Equal(t, "86400s", role.MaxTTL)
}

func TestReadDatabaseRole_404_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	_, err := c.ReadDatabaseRole(context.Background(), "database", "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteDatabaseRole_IdempotentOn404(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/database/roles/missing", r.URL.Path)
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})
	require.NoError(t, c.DeleteDatabaseRole(context.Background(), "database", "missing"),
		"404 = already gone, treated as idempotent success")
}

func TestMaskConnectionURL_RedactsPassword(t *testing.T) {
	t.Parallel()
	require.Equal(t, "user:***@tcp(db.example.com:3306)/",
		MaskConnectionURL("user:realpass@tcp(db.example.com:3306)/"),
		"real credentials redacted")
	require.Equal(t, "{{username}}:***@tcp(db.example.com:3306)/",
		MaskConnectionURL("{{username}}:{{password}}@tcp(db.example.com:3306)/"),
		"placeholder password redacted, username kept")
	require.Equal(t, "postgresql://user:***@db.example.com:5432/app",
		MaskConnectionURL("postgresql://user:pw@db.example.com:5432/app"))
	require.Equal(t, "", MaskConnectionURL(""), "empty stays empty")
}
