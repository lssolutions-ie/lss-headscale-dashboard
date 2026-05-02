package auth

import (
	"bytes"
	"image/png"

	"github.com/pquerna/otp/totp"
)

// GenerateTOTP creates a new TOTP secret and renders a 256px PNG QR code.
// Issuer is the label shown in authenticator apps; account is typically the user's email.
func GenerateTOTP(issuer, account string) (secret string, qrPNG []byte, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return "", nil, err
	}
	img, err := key.Image(256, 256)
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", nil, err
	}
	return key.Secret(), buf.Bytes(), nil
}

func VerifyTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}
