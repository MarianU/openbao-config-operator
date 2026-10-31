package v1alpha1

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mkGenSecret(charset string, length int, prefix string, rotation time.Duration) *OpenBaoGeneratedSecret {
	return &OpenBaoGeneratedSecret{
		Spec: OpenBaoGeneratedSecretSpec{
			Mount:          "secret",
			Path:           "apps/test",
			RotationPeriod: metav1.Duration{Duration: rotation},
			Generator: OpenBaoSecretGenerator{
				Key:     "value",
				Length:  length,
				Charset: charset,
				Prefix:  prefix,
			},
		},
	}
}

func TestGenerate_RespectsLengthPrefixAndCharset(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		charset string
		pool    string
	}{
		{"alphaNumSpecial", CharsetAlphaNumSpecial, genLower + genUpper + genDigits + genSymbols},
		{"alphaNum", CharsetAlphaNum, genLower + genUpper + genDigits},
		{"alpha", CharsetAlpha, genLower + genUpper},
		{"lower", CharsetLower, genLower},
		{"upper", CharsetUpper, genUpper},
		{"numeric", CharsetNumeric, genDigits},
		{"hex", CharsetHex, genDigits[:10] + "abcdef"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := mkGenSecret(tc.charset, 48, "p$", 0)
			for i := 0; i < 20; i++ {
				v, err := d.Generate()
				if err != nil {
					t.Fatalf("Generate: %v", err)
				}
				if !strings.HasPrefix(v, "p$") {
					t.Fatalf("expected prefix %q, got %q", "p$", v)
				}
				body := strings.TrimPrefix(v, "p$")
				// prefix excluded from length
				if len(body) != 48 {
					t.Fatalf("length excluding prefix = %d, want 48 (full %q)", len(body), v)
				}
				for _, ch := range body {
					if !strings.ContainsRune(tc.pool, ch) {
						t.Fatalf("char %q not in %s pool (value %q)", ch, tc.charset, v)
					}
				}
			}
		})
	}
}

func TestGenerate_DefaultLength(t *testing.T) {
	t.Parallel()
	d := mkGenSecret("", 0, "", 0) // empty charset -> alphaNumSpecial, length default 24
	v, err := d.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(v) != 24 {
		t.Fatalf("default length = %d, want 24", len(v))
	}
}

func TestGenerate_KeyDefault(t *testing.T) {
	t.Parallel()
	if got := mkGenSecret("", 8, "", 0).Key(); got != "value" {
		t.Fatalf("default key = %q, want value", got)
	}
	d := mkGenSecret("", 8, "", 0)
	d.Spec.Generator.Key = "password"
	if got := d.Key(); got != "password" {
		t.Fatalf("custom key = %q, want password", got)
	}
}

func TestGenerate_DistinctAcrossCalls(t *testing.T) {
	t.Parallel()
	d := mkGenSecret(CharsetLower, 32, "", 0)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		v, err := d.Generate()
		if err != nil {
			t.Fatal(err)
		}
		seen[v] = true
	}
	if len(seen) < 50 {
		t.Fatalf("expected 50 distinct values, got %d (non-random generator?)", len(seen))
	}
}

func TestIsEquivalentToDesiredState_Rotation(t *testing.T) {
	t.Parallel()
	now := time.Now()

	t.Run("never written -> create", func(t *testing.T) {
		d := mkGenSecret("", 8, "", time.Hour)
		if d.IsEquivalentToDesiredState(nil) != false {
			t.Fatal("want false (must write) when never generated")
		}
	})

	t.Run("fresh -> skip", func(t *testing.T) {
		d := mkGenSecret("", 8, "", time.Hour)
		d.Status.LastRotation = metav1.NewTime(now.Add(-time.Minute))
		if d.IsEquivalentToDesiredState(nil) != true {
			t.Fatal("want true (skip) while still within rotation period")
		}
	})

	t.Run("due -> write", func(t *testing.T) {
		d := mkGenSecret("", 8, "", time.Hour)
		d.Status.LastRotation = metav1.NewTime(now.Add(-2 * time.Hour))
		if d.IsEquivalentToDesiredState(nil) != false {
			t.Fatal("want false (must rotate) after period elapsed")
		}
	})

	t.Run("no rotation -> skip once written", func(t *testing.T) {
		d := mkGenSecret("", 8, "", 0) // rotationPeriod 0
		d.Status.LastRotation = metav1.NewTime(now.Add(-100 * 24 * time.Hour))
		if d.IsEquivalentToDesiredState(nil) != true {
			t.Fatal("want true (never rotate) once written")
		}
	})
}

func TestIsValid_GeneratedSecret(t *testing.T) {
	t.Parallel()
	ok, err := mkGenSecret("", 8, "", time.Hour).IsValid()
	if !ok || err != nil {
		t.Fatalf("valid secret rejected: ok=%v err=%v", ok, err)
	}
	if ok, _ := (&OpenBaoGeneratedSecret{Spec: OpenBaoGeneratedSecretSpec{Path: "data/bad"}}).IsValid(); ok {
		t.Fatal("data/-prefixed path must be rejected")
	}
	d := mkGenSecret("notACharset", 8, "", 0)
	if ok, _ := d.IsValid(); ok {
		t.Fatal("unknown charset must be rejected")
	}
	d = mkGenSecret("", 0, "", -time.Second)
	if ok, _ := d.IsValid(); ok {
		t.Fatal("negative rotationPeriod must be rejected")
	}
}

func TestRotationRequested_Annotation(t *testing.T) {
	t.Parallel()
	now := time.Now()

	// No annotation, nothing recorded -> not requested.
	d := mkGenSecret("", 8, "", time.Hour)
	if d.RotationRequested() {
		t.Fatal("no annotation should not be a rotation request")
	}

	// Empty annotation value -> ignored.
	d.Annotations = map[string]string{RotationAnnotationKey: "  "}
	if d.RotationRequested() {
		t.Fatal("empty/whitespace annotation should be ignored")
	}

	// Fresh non-empty token -> requested.
	token := "rotate-1"
	d.Annotations = map[string]string{RotationAnnotationKey: token}
	if !d.RotationRequested() {
		t.Fatal("new annotation token must be a rotation request")
	}

	// Same token recorded in status -> not requested (idempotent).
	d.Status.LastRequestedRotation = token
	d.Status.LastRotation = metav1.NewTime(now)
	if d.RotationRequested() {
		t.Fatal("already-processed token must not request rotation again")
	}

	// A NEW token -> requested again, regardless of freshness.
	d.Annotations = map[string]string{RotationAnnotationKey: "rotate-2"}
	if !d.RotationRequested() {
		t.Fatal("newer token must request rotation again")
	}
}

func TestIsEquivalentToDesiredState_OnDemand(t *testing.T) {
	t.Parallel()
	now := time.Now()

	// Fresh (within period) but a new rotation token is set -> must write.
	d := mkGenSecret("", 8, "", time.Hour)
	d.Status.LastRotation = metav1.NewTime(now.Add(-time.Minute)) // fresh
	d.Annotations = map[string]string{RotationAnnotationKey: "t1"}
	if d.IsEquivalentToDesiredState(nil) {
		t.Fatal("expected write (not equivalent) on fresh value with a pending on-demand request")
	}

	// After the operator processed t1 (lastRequestedRotation == t1) and the
	// value is fresh -> skip (idempotent, no loop).
	d.Status.LastRequestedRotation = "t1"
	if !d.IsEquivalentToDesiredState(nil) {
		t.Fatal("expected skip after processing t1 while fresh")
	}

	// Non-rotating secret (rotationPeriod 0), already written -> normally
	// never rotates, but a NEW on-demand token still forces it.
	nr := mkGenSecret("", 8, "", 0)
	nr.Status.LastRotation = metav1.NewTime(now.Add(-100 * 24 * time.Hour))
	if !nr.IsEquivalentToDesiredState(nil) {
		t.Fatal("non-rotating + no request must skip")
	}
	nr.Annotations = map[string]string{RotationAnnotationKey: "force-1"}
	if nr.IsEquivalentToDesiredState(nil) {
		t.Fatal("non-rotating secret must still rotate on explicit request")
	}
	nr.Status.LastRequestedRotation = "force-1"
	if !nr.IsEquivalentToDesiredState(nil) {
		t.Fatal("non-rotating secret must skip after processing the request")
	}
}
