package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ------------ Client ------------

type BaoClient struct {
	BaseURL     string
	Token       string
	K8sAuthPath string // e.g. "kubernetes" (default) or "k8s-prod"
	http        *http.Client
}

// NewBaoClientFromEnv builds a client from VAULT_* env vars.
// Required: VAULT_ADDR, VAULT_TOKEN
// Optional: VAULT_K8S_AUTH_PATH (default "kubernetes")
func NewBaoClientFromEnv() *BaoClient {
	addr := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	tok := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if addr == "" || tok == "" {
		panic("VAULT_ADDR and VAULT_TOKEN must be set for E2E")
	}
	// Normalize: strip trailing slash and any /ui/... suffix users might paste
	addr = strings.TrimRight(addr, "/")
	if i := strings.Index(addr, "/ui/"); i >= 0 {
		addr = addr[:i]
	}
	k8sPath := os.Getenv("VAULT_K8S_AUTH_PATH")
	if k8sPath == "" {
		k8sPath = "kubernetes"
	}

	return &BaoClient{
		BaseURL:     addr,
		Token:       tok,
		K8sAuthPath: strings.Trim(k8sPath, "/"),
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *BaoClient) do(ctx context.Context, method, path string) (*http.Response, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.Token) // Vault/OpenBao-compatible
	req.Header.Set("Accept", "application/json")
	return c.http.Do(req)
}

func readBody(r io.Reader, max int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, max))
	return string(b)
}

func statusErr(resp *http.Response, prefix string) error {
	body := readBody(resp.Body, 4096)
	return fmt.Errorf("%s: HTTP %d: %s", prefix, resp.StatusCode, strings.TrimSpace(body))
}

// ------------ Mounts (/v1/sys/mounts) ------------

type mountsResponse map[string]struct {
	Type    string            `json:"type"`
	Options map[string]string `json:"options"`
}

type Mounts mountsResponse

func (c *BaoClient) ListMounts(ctx context.Context) (Mounts, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/sys/mounts")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		return nil, statusErr(resp, "mounts")
	}
	var m mountsResponse
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return Mounts(m), nil
}

// exact key match (Vault returns keys with trailing "/")
// kv v2 has options.version == "2"
func (m Mounts) HasKVv2(path string) bool {
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	if v, ok := m[path]; ok {
		return strings.EqualFold(v.Type, "kv") && v.Options != nil && v.Options["version"] == "2"
	}
	return false
}

// ------------ Policy (/v1/sys/policies/acl/<name>) ------------

type policyResponse struct {
	Name   string `json:"name"`
	Policy string `json:"policy"` // some distros use "policy"
	Rules  string `json:"rules"`  // others use "rules"
}

func (c *BaoClient) GetPolicy(ctx context.Context, name string) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/sys/policies/acl/"+name)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("policy %q not found", name)
	}
	if resp.StatusCode >= 300 {
		return "", statusErr(resp, "get policy "+name)
	}
	var pr policyResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return "", err
	}
	if pr.Policy != "" {
		return pr.Policy, nil
	}
	return pr.Rules, nil
}

// ------------ K8s Role (/v1/auth/<mount>/role/<name>) ------------

type k8sRoleResponse struct {
	Data struct {
		BoundServiceAccountNames      []string `json:"bound_service_account_names"`
		BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
		Policies                      []string `json:"policies"`
	} `json:"data"`
}

type K8sRole struct {
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	Policies                      []string
}

func (c *BaoClient) GetK8sRole(ctx context.Context, name string) (*K8sRole, error) {
	path := fmt.Sprintf("/v1/auth/%s/role/%s", c.K8sAuthPath, name)
	resp, err := c.do(ctx, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("k8s role %q not found (mount=%q)", name, c.K8sAuthPath)
	}
	if resp.StatusCode >= 300 {
		return nil, statusErr(resp, "get k8s role "+name)
	}
	var rr k8sRoleResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, err
	}
	return &K8sRole{
		BoundServiceAccountNames:      rr.Data.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: rr.Data.BoundServiceAccountNamespaces,
		Policies:                      rr.Data.Policies,
	}, nil
}
