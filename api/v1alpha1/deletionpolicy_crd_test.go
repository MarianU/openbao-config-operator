package v1alpha1

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// Pins the generated deletionPolicy schema for every kind from
// config/crd/bases — the artifact the apiserver enforces. Fails on a
// wrong default (a pasted default=Delete on a data kind would stamp
// destruction onto every field-less CR unnoticed), enum drift, a
// group mix-up, a missing field, or the field appearing on an exempt
// kind. New CRDs fail until assigned a group here.
func TestDeletionPolicy_CRDMarkers(t *testing.T) {
	t.Parallel()

	crdDir := filepath.Join("..", "..", "config", "crd", "bases")
	prefix := "security.mto.stakater.com_"

	expected := map[string]DeletionPolicy{
		// Data-bearing kinds: destruction must be opt-in.
		prefix + "openbaosecretengines.yaml":    DeletionPolicyRetain,
		prefix + "openbaonamespaces.yaml":       DeletionPolicyRetain,
		prefix + "openbaoauthmethods.yaml":      DeletionPolicyRetain,
		prefix + "openbaokvsecrets.yaml":        DeletionPolicyRetain,
		prefix + "openbaogeneratedsecrets.yaml": DeletionPolicyRetain,
		// database connection config + role default to Retain: both are
		// data-bearing — the connection holds admin creds and is referenced
		// by roles, and a role may be actively consumed by a VSO reader.
		prefix + "openbaodatabaseengineconfigs.yaml": DeletionPolicyRetain,
		prefix + "openbaodatabaseroles.yaml":         DeletionPolicyRetain,
		// Grant kinds: revocation must stay on by default.
		prefix + "openbaopolicies.yaml":               DeletionPolicyDelete,
		prefix + "openbaokubernetesauthroles.yaml":    DeletionPolicyDelete,
		prefix + "openbaocertauthengineroles.yaml":    DeletionPolicyDelete,
		prefix + "openbaojwtoidcauthengineroles.yaml": DeletionPolicyDelete,
		prefix + "openbaopkisecretengineroles.yaml":   DeletionPolicyDelete,
		prefix + "openbaogroups.yaml":                 DeletionPolicyDelete,
		prefix + "openbaogroupaliases.yaml":           DeletionPolicyDelete,
		prefix + "openbaoidentitytokenroles.yaml":     DeletionPolicyDelete,
	}
	// Kinds that must NOT grow the field: transit + PKI config are
	// orphan-by-design (hardcoded IsDeletable=false), the auth-config
	// kinds have no bao DELETE endpoint at all.
	exempt := map[string]bool{
		prefix + "openbaotransitkeys.yaml":                 true,
		prefix + "openbaopkisecretengineconfigs.yaml":      true,
		prefix + "openbaocertauthengineconfigs.yaml":       true,
		prefix + "openbaojwtoidcauthengineconfigs.yaml":    true,
		prefix + "openbaokubernetesauthengineconfigs.yaml": true,
	}

	type crdSchema struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								// Default is `any`: other spec properties
								// carry non-string defaults (arrays, ints)
								// and must still decode.
								Properties map[string]struct {
									Default any      `json:"default"`
									Enum    []string `json:"enum"`
								} `json:"properties"`
							} `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}

	entries, err := os.ReadDir(crdDir)
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".yaml" {
			continue
		}
		seen[name] = true

		raw, err := os.ReadFile(filepath.Join(crdDir, name))
		require.NoError(t, err, name)
		var crd crdSchema
		require.NoError(t, yaml.Unmarshal(raw, &crd), name)
		require.Len(t, crd.Spec.Versions, 1, "%s: test assumes a single stored version", name)

		field, has := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Properties["deletionPolicy"]

		switch {
		case exempt[name]:
			require.False(t, has,
				"%s must not carry deletionPolicy — orphan-by-design / no DELETE endpoint", name)
		default:
			want, known := expected[name]
			require.True(t, known, "%s: new CRD — decide its deletionPolicy group and add it here", name)
			require.True(t, has, "%s: deletionPolicy field missing from generated CRD", name)
			def, ok := field.Default.(string)
			require.True(t, ok, "%s: deletionPolicy default is not a string: %v", name, field.Default)
			require.Equal(t, string(want), def, "%s: wrong deletionPolicy default", name)
			gotEnum := append([]string(nil), field.Enum...)
			sort.Strings(gotEnum)
			require.Equal(t, []string{string(DeletionPolicyDelete), string(DeletionPolicyRetain)}, gotEnum,
				"%s: deletionPolicy enum drifted", name)
		}
	}

	for name := range expected {
		require.True(t, seen[name], "expected CRD file %s not found — regenerate manifests or update this test", name)
	}
	for name := range exempt {
		require.True(t, seen[name], "exempt CRD file %s not found — regenerate manifests or update this test", name)
	}
}
