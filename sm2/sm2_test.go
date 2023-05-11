package sm2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("priv:%s\n", priv.D.Text(16))
	fmt.Printf("x:%s\n", priv.PublicKey.X.Text(16))
	fmt.Printf("y:%s\n", priv.PublicKey.Y.Text(16))

	curve := GetSm2P256V1()
	if !curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Error("x,y is not on Curve")
		return
	}
	fmt.Println("x,y is on sm2 Curve")
}

func TestSignVerify(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	inBytes := []byte("123")

	sign, err := priv.SignDigest(rand.Reader, inBytes, nil)
	if err != nil {
		t.Error(err.Error())
		return
	}

	sign, err := Sign(rand.Reader, priv, inBytes, nil)

	fmt.Println("raw sign:", base64.RawStdEncoding.EncodeToString(sign))

	result := Verify(&priv.PublicKey, inBytes, nil, sign)

	result := priv.PublicKey.VerifyDigest(inBytes, nil, sign)
	if !result {
		t.Error("verify failed")
		return
	}

	fmt.Printf("raw sign verify result: %v \n", result)

	digest, _ := priv.PublicKey.SM3Digest(inBytes, nil)

	sign, err = SignDigest(rand.Reader, priv, digest)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Println("digest sign:", base64.RawStdEncoding.EncodeToString(sign))

	result = Verify(&priv.PublicKey, inBytes, nil, sign)
	if !result {
		t.Error("digest sign verify failed")
		return
	}

	fmt.Printf("digest sign verify use plain result: %v \n", result)

	result = VerifyDigest(&priv.PublicKey, digest, sign)
	if !result {
		t.Error("digest sign verify failed")
		return
	}

	fmt.Printf("digest sign verify use digest result: %v \n", result)

}
