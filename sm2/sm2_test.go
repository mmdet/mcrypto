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

	encgmsm, _ := hex.DecodeString("4bffdb953626efba7fd5876b13f228eb338652b552e8b556a343d6ed19305ebe7d10983b8523746b53fa8f816bc1b6ec26777e3c743b671302157b3ad82a529a50ceea710f7f3d7cdd57a7458c3c9b4108dd6a71c24ec29fc35154d10be3c7595cd460")

	decgmsm, _ := Decryt(priv, encgmsm)
	fmt.Println("decgmsm", string(decgmsm))

	encgm, _ := hex.DecodeString("0a3d3e86b919d9a76fdb9c95f0f749755e5cec9183ecac2e9a06250dec2a0c134187b6d2234c912167958429625c71ded18ac31e93df207f1b0bb79a55222c9e09041f92507a649f227d15b59b1733c13cc6fb2c33e3ea7271b571839f369e2ad02836")

	decgm, _ := Decryt(priv, encgm)
	fmt.Println("decgm", string(decgm))

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
