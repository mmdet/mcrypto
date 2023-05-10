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
### 密钥对生成
mcrypto定义了`sm2.PublicKey`和`sm2.PrivateKey`表示SM2算法的公私钥对，并实现了标准库的`crypto.PublicKey`和`crypto.PrivateKey`。

```go
priv, err := GenerateKey(rand.Reader)
if err != nil {
	t.Error(err.Error())
	return
}
fmt.Printf("priv:%s\n", priv.D.Text(16))
fmt.Printf("x:%s\n", priv.PublicKey.X.Text(16))
fmt.Printf("y:%s\n", priv.PublicKey.Y.Text(16))
```