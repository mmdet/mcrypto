<p align="center">
	<a href=""><img src="logo.png" width="200px"></a>
</p>
<p align="center">
	<strong>对GO语言标准库crypto的扩展,支持国产SM系列算法</strong>
</p>

<p align="center">
  <a target="_blank" href="">
		<img src="https://img.shields.io/badge/release-v1.0.1-blue.svg" />
	</a>
	<a target="_blank" href="https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html">
		<img src="https://img.shields.io/badge/Go-1.18+-green.svg" />
	</a>
	<a target="_blank" href="">
		<img src="https://img.shields.io/badge/build-passing-green.svg" />
	</a>
	<a href="https://www.apache.org/licenses/LICENSE-2.0">
		<img src="https://img.shields.io/badge/License-Apache--2.0-red.svg"/>
	</a>
</p>



-------------------------------------------------------------------------------
## 使用
```go
go get github.com/mmdet/mcrypto@latest
```

## SM3杂凑算法
实现了标准库的`hash.Hash`接口，同标准库的Hash算法使用保持了一致。
```go
h := sm3.New()
h.Write([]byte("123"))
fmt.Printf("%x \n", h.Sum(nil))
```
## SM2非对称算法
### 1.密钥对生成
`sm2.PublicKey`和`sm2.PrivateKey`表示SM2算法的公私钥对，并实现了标准库的`crypto.PublicKey`和`crypto.PrivateKey`，使用上与RSA、ECDSA等其他算法的密钥对使用方式一致。
```go
priv, err := sm2.GenerateKey(rand.Reader)
if err != nil {
	t.Error(err.Error())
	return
}
fmt.Printf("priv:%s\n", priv.D.Text(16))
fmt.Printf("x:%s\n", priv.PublicKey.X.Text(16))
fmt.Printf("y:%s\n", priv.PublicKey.Y.Text(16))
```
### 2.加解密

### 3.数字签名
mcrypto提供了对原文签名和对摘要签名这两种待签名数据输入形式的签名。
#### 3.1对原文签名与验证
签名：
```go
inBytes := []byte("123")
useIdBytes := []byte("1234567812345678")

sign, err := sm2.Sign(rand.Reader, sm2.PrivateKey, inBytes, useIdBytes)
if err != nil {
	t.Error(err.Error())
	return
}
```
验证：
```go
result := sm2.Verify(&sm2.PublicKey, inBytes, useIdBytes, sign)
if !result {
	t.Error("verify failed")
	return
}
```
#### 3.2对摘要签名
这种签名方式，需要调用者事先自己计算原文的摘要。

由于SM2签名时SM2公钥需要参与计算，sm2.PublicKey提供了该函数。
```go
pub:=sm2.PublicKey
digest, _ := pub.SM3Digest(inBytes, useIdBytes)
```
将上面计算的`digest`签名：
```go
sign, err = sm2.SignDigest(rand.Reader, sm2.PrivateKey, digest)
if err != nil {
	t.Error(err.Error())
	return
}
```
摘要签名验证：
```go
result = sm2.VerifyDigest(sm2.PublicKey, digest, sign)
if !result {
	t.Error("digest sign verify failed")
	return
}
```
或者，使用原文验证：
```go
result = Verify(sm2.PublicKey, inBytes, useIdBytes, sign)
if !result {
	t.Error("digest sign verify failed")
	return
}
```