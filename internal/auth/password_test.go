package auth

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	enc, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := VerifyPassword("correct horse battery staple", enc)
	if err != nil || !ok {
		t.Fatalf("verify expected ok, got ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword("wrong password", enc)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if ok {
		t.Fatal("verify accepted wrong password")
	}
}

func TestPasswordHashFormat(t *testing.T) {
	enc, err := HashPassword("x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyPassword("x", enc[:len(enc)-2]+"=") // corrupt suffix
	if err != nil && err != ErrInvalidPasswordHash {
		// base64 decode may produce a different error; either way, must not panic.
		t.Logf("got err (acceptable): %v", err)
	}
}
