package x509

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/mmdet/mcrypto/sm2"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("priv:%s\n", priv.D.Text(16))
	fmt.Printf("x:%s\n", priv.PublicKey.X.Text(16))
	fmt.Printf("y:%s\n", priv.PublicKey.Y.Text(16))

	bytepk, _ := MarshalPKCS8PrivateKey(priv)
	//
	bytesss, _ := MarshalPKIXPublicKey(&priv.PublicKey)
	//
	fmt.Printf("pkcs8 privatekey:%s \n", base64.StdEncoding.EncodeToString(bytepk))
	//
	fmt.Printf("x509 publickey:%s \n", base64.RawStdEncoding.EncodeToString(bytesss))

}

func TestParseKey(t *testing.T) {
	data := []byte("123")
	pubs := "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEd+Q6yBmwfG5Btol/cC6vi3eHGQ30N2CGMMHxc5qXiPcvoIwCRy3XvCHwBVZ1mXX6r7mxHIK3bAe3YwPWvKLOIA=="
	priv := "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgBm4hIxqnPJZKHFT1fdicLiLC6W34BpkWgd6oBveI/1egCgYIKoEcz1UBgi2hRANCAAR35DrIGbB8bkG2iX9wLq+Ld4cZDfQ3YIYwwfFzmpeI9y+gjAJHLde8IfAFVnWZdfqvubEcgrdsB7djA9a8os4g"

	sig := "MEYCIQC8C3TTXe2d5omZTzVkBMlEKQOdLtAzB+KoRwtA3i3NpgIhALLqKHl3VrtxaHkuFNqXaT6Th1OGUfIaG9BQXZUyx9c+"
	pubytes, err := base64.StdEncoding.DecodeString(pubs)
	pub, err := ParsePKIXPublicKey(pubytes)
	sigbytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
	case *dsa.PublicKey:
		fmt.Println("pub is of type DSA:", pub)
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub)
	case *sm2.PublicKey:
		fmt.Println("pub is of type SM2:", pub)
		Verify(t, pub, data, sigbytes)
	case ed25519.PublicKey:
		fmt.Println("pub is of type Ed25519:", pub)
	default:
		panic("unknown type of public key")
	}

	pribytes, _ := base64.StdEncoding.DecodeString(priv)
	pri, err := ParsePKCS8PrivateKey(pribytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	switch pri := pri.(type) {
	case *rsa.PrivateKey:
		fmt.Println("pri is of type RSA:", pri)
	case *dsa.PrivateKey:
		fmt.Println("pri is of type DSA:", pri)
	case *ecdsa.PrivateKey:
		fmt.Println("pri is of type ECDSA:", pri)
	case *sm2.PrivateKey:
		fmt.Println("pri is of type SM2:", pri)
		Sign(t, pri, data)
	case ed25519.PrivateKey:
		fmt.Println("pri is of type Ed25519:", pri)
	default:
		panic("unknown type of private key")
	}
}

func Verify(t *testing.T, pub *sm2.PublicKey, in, sig []byte) {
	result := sm2.Verify(pub, in, nil, sig)
	if !result {
		t.Error("signature verify failed")
		return
	}
	fmt.Printf("signature verify success: %v \n", result)
}

func Sign(t *testing.T, pri *sm2.PrivateKey, in []byte) {
	result, err := sm2.Sign(rand.Reader, pri, in, nil)
	if err != nil {
		t.Error("signature failed")
		return
	}

	fmt.Printf("signature success: %v \n", base64.StdEncoding.EncodeToString(result))
}

func TestParseCert(t *testing.T) {
	cert := "MIIDVjCCAvygAwIBAgINAJCtcQi1xWgoiFu50TAKBggqgRzPVQGDdTAgMQswCQYDVQQGEwJDTjERMA8GA1UEAwwIc20yX3Jvb3QwHhcNMjExMjA3MjIxNjQ1WhcNMzkxMjA3MTYwMDAwWjBlMQ8wDQYDVQQIDAbnoJTlj5ExEjAQBgNVBAcMCeWNl+S6rOW4gjENMAsGA1UECgwEc3lhbjESMBAGA1UECwwJ56CU5Y+R6YOoMRswGQYDVQQDDBJzcGFya1/pgJrorq/or4HkuaYwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATbf6mIrEzgpIv1RiRVMl7cRNbzTYay9AknqdEjNflw7WQ2Nz8yAQvireaHFVX6mogKwXvfwqceoF/9Woil9ypoo4IB1DCCAdAwCQYDVR0TBAIwADAdBgNVHQ4EFgQUk2lZgdL1LctBlyyLk6YJzTanbuowDgYDVR0PAQH/BAQDAgD/MIGbBgNVHSUBAf8EgZAwgY0GCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCAYKKwYBBAGCNwIBFQYKKwYBBAGCNwIBFgYKKwYBBAGCNwoDAQYKKwYBBAGCNwoDAwYKKwYBBAGCNwoDBAYJYIZIAYb4QgQBBggrBgEFBQcDCQYIKwYBBQUHAwowLgYDVR0fBCcwJTAjoCGgH4YdaHR0cHM6Ly9haWEuc3lhbi5jb20uY24vY3JsL2EwYgYIKwYBBQUHAQEEVjBUMCQGCCsGAQUFBzABhhhodHRwczovL29jc3Auc3lhbi5jb20uY24wLAYIKwYBBQUHMAKGIGh0dHBzOi8vYWlhLnN5YW4uY29tLmNuL2lzc3Vlci9hMB8GA1UdIwQYMBaAFE62EA55ojyyltMkTdh/2Ac4lpUEMEEGA1UdIAQ6MDgwNgYIKoEchvAAZAEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9jcHMuc3lhbi5jb20uY24vY3BzMTAKBggqgRzPVQGDdQNIADBFAiEAmKlOSDGvzcD/Z19/5zIItoTtaUa02I8+lJoaz4SSGdoCIExCV6F474ctRWqFt3sEHC9pi1QJuglYSmSdXgMvVTYm"
	der, _ := base64.StdEncoding.DecodeString(cert)
	c, err := parseCertificate(der)
	if err != nil {
		t.Error(err)
		return
	}
	//fmt.Printf(c.Subject.CommonName)
	publikeyDer, err := MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf(hex.EncodeToString(publikeyDer))
}
