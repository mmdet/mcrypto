package sm2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
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

	curve := SM2P256V1()
	if !curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Error("x,y is not on Curve")
		return
	}
	fmt.Println("x,y is on sm2 Curve")
}

func TestSignVerify1(t *testing.T) {

	curve := SM2P256V1()
	xBytes, _ := hex.DecodeString("6177de723b90680bbc2f7a1f77e3e2744f148d8b3b929a1144f8dff7d3afa5a8")
	yBytes, _ := hex.DecodeString("41b449bd631687ff04de337b6b6799b7387051e8180750df79d211f01177a094")
	dBytes, _ := hex.DecodeString("8ddc002fed820eb7fcb8c8f023c2f822390e0a004cd0939d13436cd239e472ab")

	priv := new(PrivateKey)
	priv.PublicKey.Curve = curve
	priv.PublicKey.X = new(big.Int).SetBytes(xBytes)
	priv.PublicKey.Y = new(big.Int).SetBytes(yBytes)
	priv.D = new(big.Int).SetBytes(dBytes)

	inBytes := []byte("1234")

	sign, err := priv.Sign(rand.Reader, inBytes, nil)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Println("raw sign:", base64.RawStdEncoding.EncodeToString(sign))
	result := priv.PublicKey.Verify(inBytes, nil, sign)
	if !result {
		fmt.Println("priv.PublicKey verify failed")
	}
	result = Verify(&priv.PublicKey, inBytes, nil, sign)
	if !result {
		fmt.Println("sm2.verify failed")
	} else {
		fmt.Println("sm2.verify success")
	}

	enc, err := Encryt(rand.Reader, &priv.PublicKey, inBytes)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Println("enc", hex.EncodeToString(enc))

	dec, err := Decryt(priv, enc)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Println("dec", string(dec))
}

func TestSignVerify2(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	inBytes := []byte("123")

	sign, err := Sign(rand.Reader, priv, inBytes, nil)
	if err != nil {
		t.Error(err.Error())
		return
	}

	fmt.Println("raw sign:", base64.RawStdEncoding.EncodeToString(sign))

	result := Verify(&priv.PublicKey, inBytes, nil, sign)

	if !result {
		t.Error("verify failed")
		return
	}

	fmt.Printf("raw sign verify result: %v \n", result)
}

func TestSignVerify3(t *testing.T) {

	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	inBytes := []byte("123")

	sign, err := priv.SignDigest(rand.Reader, inBytes)
	if err != nil {
		t.Error(err.Error())
		return
	}

	//sign, err := Sign(rand.Reader, priv, inBytes, nil)

	fmt.Println("raw sign:", base64.RawStdEncoding.EncodeToString(sign))

	result := Verify(&priv.PublicKey, inBytes, nil, sign)

	//result := priv.PublicKey.VerifyDigest(inBytes, sign)
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

func TestEncrypt(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	inBytes := []byte("1234")
	enc, err := Encryt(rand.Reader, &priv.PublicKey, inBytes)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Println("enc", hex.EncodeToString(enc))

	dec, err := Decryt(priv, enc)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Println("dec", string(dec))
}
