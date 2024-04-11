package x509

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mmdet/mcrypto/sm2"
	"testing"
)

func TestSignedData(t *testing.T) {
	data := []byte("123")
	cert := "MIIDVjCCAvygAwIBAgINAJCtcQi1xWgoiFu50TAKBggqgRzPVQGDdTAgMQswCQYDVQQGEwJDTjERMA8GA1UEAwwIc20yX3Jvb3QwHhcNMjExMjA3MjIxNjQ1WhcNMzkxMjA3MTYwMDAwWjBlMQ8wDQYDVQQIDAbnoJTlj5ExEjAQBgNVBAcMCeWNl+S6rOW4gjENMAsGA1UECgwEc3lhbjESMBAGA1UECwwJ56CU5Y+R6YOoMRswGQYDVQQDDBJzcGFya1/pgJrorq/or4HkuaYwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATbf6mIrEzgpIv1RiRVMl7cRNbzTYay9AknqdEjNflw7WQ2Nz8yAQvireaHFVX6mogKwXvfwqceoF/9Woil9ypoo4IB1DCCAdAwCQYDVR0TBAIwADAdBgNVHQ4EFgQUk2lZgdL1LctBlyyLk6YJzTanbuowDgYDVR0PAQH/BAQDAgD/MIGbBgNVHSUBAf8EgZAwgY0GCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCAYKKwYBBAGCNwIBFQYKKwYBBAGCNwIBFgYKKwYBBAGCNwoDAQYKKwYBBAGCNwoDAwYKKwYBBAGCNwoDBAYJYIZIAYb4QgQBBggrBgEFBQcDCQYIKwYBBQUHAwowLgYDVR0fBCcwJTAjoCGgH4YdaHR0cHM6Ly9haWEuc3lhbi5jb20uY24vY3JsL2EwYgYIKwYBBQUHAQEEVjBUMCQGCCsGAQUFBzABhhhodHRwczovL29jc3Auc3lhbi5jb20uY24wLAYIKwYBBQUHMAKGIGh0dHBzOi8vYWlhLnN5YW4uY29tLmNuL2lzc3Vlci9hMB8GA1UdIwQYMBaAFE62EA55ojyyltMkTdh/2Ac4lpUEMEEGA1UdIAQ6MDgwNgYIKoEchvAAZAEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9jcHMuc3lhbi5jb20uY24vY3BzMTAKBggqgRzPVQGDdQNIADBFAiEAmKlOSDGvzcD/Z19/5zIItoTtaUa02I8+lJoaz4SSGdoCIExCV6F474ctRWqFt3sEHC9pi1QJuglYSmSdXgMvVTYm"
	der, _ := base64.StdEncoding.DecodeString(cert)
	c, err := parseCertificate(der)
	if err != nil {
		t.Error(err)
		return
	}

	pkey := "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg3QUJl8oln93Zp5QuE39kgGxp+/lt0vJBGfT8GmjfETChRANCAATbf6mIrEzgpIv1RiRVMl7cRNbzTYay9AknqdEjNflw7WQ2Nz8yAQvireaHFVX6mogKwXvfwqceoF/9Woil9ypo"
	pribytes, _ := base64.StdEncoding.DecodeString(pkey)
	pri, err := ParsePKCS8PrivateKey(pribytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}

	p7, err := NewSignedData(c, pri, data)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	fmt.Println(base64.StdEncoding.EncodeToString(p7))

	Stringpkcs777 := "MIIEpgYKKoEcz1UGAQQCAqCCBJYwggSSAgEBMQwwCgYIKoEcz1UBgxEwFgYKKoEcz1UGAQQCAaAIBAYxMjM0NTagggNaMIIDVjCCAvygAwIBAgINAJCtcQi1xWgoiFu50TAKBggqgRzPVQGDdTAgMQswCQYDVQQGEwJDTjERMA8GA1UEAwwIc20yX3Jvb3QwHhcNMjExMjA3MjIxNjQ1WhcNMzkxMjA3MTYwMDAwWjBlMQ8wDQYDVQQIDAbnoJTlj5ExEjAQBgNVBAcMCeWNl+S6rOW4gjENMAsGA1UECgwEc3lhbjESMBAGA1UECwwJ56CU5Y+R6YOoMRswGQYDVQQDDBJzcGFya1/pgJrorq/or4HkuaYwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATbf6mIrEzgpIv1RiRVMl7cRNbzTYay9AknqdEjNflw7WQ2Nz8yAQvireaHFVX6mogKwXvfwqceoF/9Woil9ypoo4IB1DCCAdAwCQYDVR0TBAIwADAdBgNVHQ4EFgQUk2lZgdL1LctBlyyLk6YJzTanbuowDgYDVR0PAQH/BAQDAgD/MIGbBgNVHSUBAf8EgZAwgY0GCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCAYKKwYBBAGCNwIBFQYKKwYBBAGCNwIBFgYKKwYBBAGCNwoDAQYKKwYBBAGCNwoDAwYKKwYBBAGCNwoDBAYJYIZIAYb4QgQBBggrBgEFBQcDCQYIKwYBBQUHAwowLgYDVR0fBCcwJTAjoCGgH4YdaHR0cHM6Ly9haWEuc3lhbi5jb20uY24vY3JsL2EwYgYIKwYBBQUHAQEEVjBUMCQGCCsGAQUFBzABhhhodHRwczovL29jc3Auc3lhbi5jb20uY24wLAYIKwYBBQUHMAKGIGh0dHBzOi8vYWlhLnN5YW4uY29tLmNuL2lzc3Vlci9hMB8GA1UdIwQYMBaAFE62EA55ojyyltMkTdh/2Ac4lpUEMEEGA1UdIAQ6MDgwNgYIKoEchvAAZAEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9jcHMuc3lhbi5jb20uY24vY3BzMTAKBggqgRzPVQGDdQNIADBFAiEAmKlOSDGvzcD/Z19/5zIItoTtaUa02I8+lJoaz4SSGdoCIExCV6F474ctRWqFt3sEHC9pi1QJuglYSmSdXgMvVTYmMYIBBzCCAQMCAQEwMTAgMQswCQYDVQQGEwJDTjERMA8GA1UEAwwIc20yX3Jvb3QCDQCQrXEItcVoKIhbudEwCgYIKoEcz1UBgxGgaTAYBgkqhkiG9w0BCQMxCwYJKoEcz1UGAQQCMBwGCSqGSIb3DQEJBTEPFw0yMzA0MjAwMjMwMjhaMC8GCSqGSIb3DQEJBDEiBCAgfPQQUy+SpH3uJFzpsR/3H1eOvXY+s7vqROvQQ9AY+zALBgkqgRzPVQGCLQEERzBFAiBXpUKZy2JBiyifYjFq+4C1XzF5F4/WWcHU66HDxs2KFAIhAOiBgjErxRQok07gY5nCQWblfJDLwfRqmpEm/838CJc7"

	p7, _ = base64.StdEncoding.DecodeString(Stringpkcs777)

	PKCS7, err := ParsePKCS7(p7)

	if err != nil {
		panic("failed to parse PKCS7:" + err.Error())
	}
	fmt.Println(string(PKCS7.Content))

	err = PKCS7.Verify()

	if err != nil {
		panic("failed to verify PKCS7:" + err.Error())
	}
}

func pkcascallback(attrBytes []byte) ([]byte, error) {

	pkey := "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg3QUJl8oln93Zp5QuE39kgGxp+/lt0vJBGfT8GmjfETChRANCAATbf6mIrEzgpIv1RiRVMl7cRNbzTYay9AknqdEjNflw7WQ2Nz8yAQvireaHFVX6mogKwXvfwqceoF/9Woil9ypo"
	pribytes, _ := base64.StdEncoding.DecodeString(pkey)
	pri, err := ParsePKCS8PrivateKey(pribytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	switch priv := pri.(type) {
	case *sm2.PrivateKey:
		return sm2.Sign(rand.Reader, priv, attrBytes, nil)
	}
	return nil, errors.New("unsupport algop")

}
func TestSignedDataCallback(t *testing.T) {

	data := []byte("123")
	cert := "MIIDVjCCAvygAwIBAgINAJCtcQi1xWgoiFu50TAKBggqgRzPVQGDdTAgMQswCQYDVQQGEwJDTjERMA8GA1UEAwwIc20yX3Jvb3QwHhcNMjExMjA3MjIxNjQ1WhcNMzkxMjA3MTYwMDAwWjBlMQ8wDQYDVQQIDAbnoJTlj5ExEjAQBgNVBAcMCeWNl+S6rOW4gjENMAsGA1UECgwEc3lhbjESMBAGA1UECwwJ56CU5Y+R6YOoMRswGQYDVQQDDBJzcGFya1/pgJrorq/or4HkuaYwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATbf6mIrEzgpIv1RiRVMl7cRNbzTYay9AknqdEjNflw7WQ2Nz8yAQvireaHFVX6mogKwXvfwqceoF/9Woil9ypoo4IB1DCCAdAwCQYDVR0TBAIwADAdBgNVHQ4EFgQUk2lZgdL1LctBlyyLk6YJzTanbuowDgYDVR0PAQH/BAQDAgD/MIGbBgNVHSUBAf8EgZAwgY0GCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCAYKKwYBBAGCNwIBFQYKKwYBBAGCNwIBFgYKKwYBBAGCNwoDAQYKKwYBBAGCNwoDAwYKKwYBBAGCNwoDBAYJYIZIAYb4QgQBBggrBgEFBQcDCQYIKwYBBQUHAwowLgYDVR0fBCcwJTAjoCGgH4YdaHR0cHM6Ly9haWEuc3lhbi5jb20uY24vY3JsL2EwYgYIKwYBBQUHAQEEVjBUMCQGCCsGAQUFBzABhhhodHRwczovL29jc3Auc3lhbi5jb20uY24wLAYIKwYBBQUHMAKGIGh0dHBzOi8vYWlhLnN5YW4uY29tLmNuL2lzc3Vlci9hMB8GA1UdIwQYMBaAFE62EA55ojyyltMkTdh/2Ac4lpUEMEEGA1UdIAQ6MDgwNgYIKoEchvAAZAEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9jcHMuc3lhbi5jb20uY24vY3BzMTAKBggqgRzPVQGDdQNIADBFAiEAmKlOSDGvzcD/Z19/5zIItoTtaUa02I8+lJoaz4SSGdoCIExCV6F474ctRWqFt3sEHC9pi1QJuglYSmSdXgMvVTYm"
	der, _ := base64.StdEncoding.DecodeString(cert)
	c, err := parseCertificate(der)
	if err != nil {
		t.Error(err)
		return
	}

	p7, err := NewSignedDataCallBack(c, func(attrBytes []byte) ([]byte, error) {
		pkey := "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg3QUJl8oln93Zp5QuE39kgGxp+/lt0vJBGfT8GmjfETChRANCAATbf6mIrEzgpIv1RiRVMl7cRNbzTYay9AknqdEjNflw7WQ2Nz8yAQvireaHFVX6mogKwXvfwqceoF/9Woil9ypo"
		pribytes, _ := base64.StdEncoding.DecodeString(pkey)
		pri, err := ParsePKCS8PrivateKey(pribytes)
		if err != nil {
			panic("failed to parse DER encoded private key: " + err.Error())
		}
		switch priv := pri.(type) {
		case *sm2.PrivateKey:
			return sm2.Sign(rand.Reader, priv, attrBytes, nil)
		}
		return nil, errors.New("unsupport algop")
	}, data)

	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	fmt.Println("p7", base64.StdEncoding.EncodeToString(p7))

	Stringpkcs777 := base64.StdEncoding.EncodeToString(p7)

	p7, _ = base64.StdEncoding.DecodeString(Stringpkcs777)

	PKCS7, err := ParsePKCS7(p7)

	if err != nil {
		panic("failed to parse PKCS7:" + err.Error())
	}
	fmt.Println(string(PKCS7.Content))

	err = PKCS7.Verify()

	if err != nil {
		panic("failed to verify PKCS7:" + err.Error())
	}
}

func TestSignedDataVerify(t *testing.T) {

	Stringpkcs777 := "30820323060a2a811ccf550601040202a08203133082030f020101310c300a06082a811ccf550183113023060a2a811ccf550601040201a01504137b2274696d65223a313730313835313533327da08201c2308201be30820165a003020102020d00d449091b36787c5cdd9b2d0c300a06082a811ccf550183753020310b300906035504061302434e3111300f06035504030c08534d325f524f4f543020170d3233303632313231303133345a180f32303530303632313136303030305a3026310b300906035504061302434e3117301506035504030c0e63636d67725f706c6174666f726d3059301306072a8648ce3d020106082a811ccf5501822d034200047e10211878b653ec26603e8a7225963bce8f97c2fa4fd309aea114f53ad31393b0a74d4a17f31916448d95019ff58365a27a015d1185238270d36532dc676377a37c307a30090603551d1304023000301d0603551d0e04160414c1a7cd9374fa0c58735773ba1780d9d65aa53983301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d23041830168014746a24a52cf8324a0b4ec1793f776031efcd832a300e0603551d0f0101ff0404030203f8300a06082a811ccf55018375034700304402204701447eba1125e3f03488dd71c047d83d4cb95c83bc006897537280eb5be99d0220640de17308c357670ecf8638f73762ead895bc18784771839bb9f734319f96eba1003182010d3082010902010130313020310b300906035504061302434e3111300f06035504030c08534d325f524f4f54020d00d449091b36787c5cdd9b2d0c300a06082a811ccf55018311a06e301906092a864886f70d010903310c060a2a811ccf550601040201302006092a864886f70d010905311317113233313230363136333231322b30383030302f06092a864886f70d0109043122042041bb0400ab8c434772951c296cb8ab4d6101d6b9f9c55cc9d6f9ede0162f6569300b06092a811ccf5501822d0104483046022100cdd24255b1897af465ad4365e4b8df7d9dd80fa0a6cc05f1a66b5c3e1e21d08d02210095778f9d4188d59100b0adce5ee9e46fa9c464d1219e7eea8a6a1f89a410b5df"

	p7, _ := hex.DecodeString(Stringpkcs777)

	PKCS7, err := ParsePKCS7(p7)

	if err != nil {
		panic("failed to parse PKCS7:" + err.Error())
	}
	fmt.Println(string(PKCS7.Content))

	err = PKCS7.Verify()

	if err != nil {
		panic("failed to verify PKCS7:" + err.Error())
	}
}

func TestSignVerify4(t *testing.T) {

	in := "316e301906092a864886f70d010903310c060a2a811ccf550601040201302006092a864886f70d010905311317113233313230363136353931382b30383030302f06092a864886f70d01090431220420ab281cd7c0488cac5f780690fe8349434f081287b0f30669b8d4f15857ddb44b"
	sign := "304502206a1ca59f5b5114cb567d614e35ef253bcb3d1773c215d04b1865996655002b7f022100eca82440427e532faf7410c5a11015e0ee3fd153209ab00a1275ba681f0f2d68"

	inbytes, _ := hex.DecodeString(in)
	signbytes, _ := hex.DecodeString(sign)
	ert := "MIIBvjCCAWWgAwIBAgINANRJCRs2eHxc3ZstDDAKBggqgRzPVQGDdTAgMQswCQYDVQQGEwJDTjERMA8GA1UEAwwIU00yX1JPT1QwIBcNMjMwNjIxMjEwMTM0WhgPMjA1MDA2MjExNjAwMDBaMCYxCzAJBgNVBAYTAkNOMRcwFQYDVQQDDA5jY21ncl9wbGF0Zm9ybTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABH4QIRh4tlPsJmA+inIlljvOj5fC+k/TCa6hFPU60xOTsKdNShfzGRZEjZUBn/WDZaJ6AV0RhSOCcNNlMtxnY3ejfDB6MAkGA1UdEwQCMAAwHQYDVR0OBBYEFMGnzZN0+gxYc1dzuheA2dZapTmDMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBR0aiSlLPgySgtOwXk/d2Ax782DKjAOBgNVHQ8BAf8EBAMCA/gwCgYIKoEcz1UBg3UDRwAwRAIgRwFEfroRJePwNIjdccBH2D1MuVyDvABol1NygOtb6Z0CIGQN4XMIw1dnDs+GOPc3YurYlbwYeEdxg5u59zQxn5br"
	p, _ := base64.StdEncoding.DecodeString(ert)

	c, err := ParseCertificate(p)
	if err != nil {
		fmt.Println(err)
		return
	}
	pub := c.PublicKey
	switch pub := pub.(type) {
	case *sm2.PublicKey:
		verify := sm2.Verify(pub, inbytes, nil, signbytes)
		fmt.Println("验证结果：", verify)
		break
	}

}

func TestHexToBase64(t *testing.T) {
	hhex := "3046022100DF8B9818C933F9FA860419CEBD4EF0D1471713B37AD4F62D634EADDA706188C10221008F8151C59BB330355B6B4753E939C6C1061F504B49EDFC9CAF14DEEC0E7D49D9"
	inbytes, _ := hex.DecodeString(hhex)
	bbase64 := base64.StdEncoding.EncodeToString(inbytes)
	fmt.Println(bbase64)
	bbase642 := base64.StdEncoding.EncodeToString([]byte("123"))
	fmt.Println(bbase642)
}
