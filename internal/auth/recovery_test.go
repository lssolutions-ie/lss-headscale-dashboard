package auth

import (
	"strings"
	"testing"
)

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("want 10, got %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		parts := strings.Split(c, "-")
		if len(parts) != 3 {
			t.Errorf("bad format: %q", c)
		}
		for _, p := range parts {
			if len(p) != 4 {
				t.Errorf("each block must be 4 chars: %q", c)
			}
		}
		if seen[c] {
			t.Errorf("duplicate code: %q", c)
		}
		seen[c] = true
	}
}

func TestHashRecoveryCodeNormalizes(t *testing.T) {
	a := HashRecoveryCode("ABCD-EFGH-IJKL")
	b := HashRecoveryCode("abcdefghijkl")
	c := HashRecoveryCode("aBcD-eFgH-iJkL")
	if a != b || b != c {
		t.Fatalf("hashes differ across formats: %s %s %s", a, b, c)
	}
}
