package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateRecoveryCodes returns n single-use codes in the form "XXXX-XXXX-XXXX"
// (12 base32 chars, ~60 bits of entropy). Show plaintext to the user once;
// store HashRecoveryCode(plaintext) in the DB.
func GenerateRecoveryCodes(n int) ([]string, error) {
	out := make([]string, n)
	for i := range out {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		s := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
		// 13 chars from 8 bytes; format as XXXX-XXXX-XXXX (12 chars used).
		s = s[:12]
		out[i] = fmt.Sprintf("%s-%s-%s", s[:4], s[4:8], s[8:12])
	}
	return out, nil
}

func HashRecoveryCode(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
