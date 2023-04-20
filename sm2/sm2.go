package sm2

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"github.com/mmdet/mcrypto/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"hash"
	"io"
	"math/big"
)

var (
	errZeroParam         = errors.New("zero parameter")
	one                  = new(big.Int).SetInt64(1)
	sm2SignDefaultUserId = []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

var sm2P256V1 P256V1Curve

//自定义SM2的椭圆曲线
type P256V1Curve struct {
	*elliptic.CurveParams
	A *big.Int
}

func init() {
	initSm2P256V1()
}

func GetSm2P256V1() P256V1Curve {
	return sm2P256V1
}

func (curve P256V1Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

//初始化SM2的椭圆曲线参数
func initSm2P256V1() {
	sm2P, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2N, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2Gx, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256V1.CurveParams = &elliptic.CurveParams{
		P: sm2P, N: sm2N, B: sm2B, Gx: sm2Gx, Gy: sm2Gy, BitSize: 256, Name: "sm2p256v1"}
	sm2P256V1.A = sm2A
}

// PublicKey represents an SM2 public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey represents an SM2 private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

//implement crypto.PrivateKey
// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

//implement crypto.PrivateKey
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && priv.D.Cmp(xx.D) == 0
}

//implement crypto.PublicKey
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.X.Cmp(xx.X) == 0 && pub.Y.Cmp(xx.Y) == 0 &&
		pub.Curve == xx.Curve
}

//生成SM2密钥对
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	priv, x, y, err := elliptic.GenerateKey(sm2P256V1, random)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: sm2P256V1,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(priv),
	}, err
}

//原文裸签，返回R||S
func (priv *PrivateKey) SignRS(rand io.Reader, in, uid []byte) (r, s *big.Int, err error) {
	return SignRS(rand, priv, in, uid)
}

//原文裸签,返回DER编码的签名
func (priv *PrivateKey) Sign(rand io.Reader, in, uid []byte) ([]byte, error) {
	return Sign(rand, priv, in, uid)
}

//摘要签名，返回R||S
func (priv *PrivateKey) SignDigestRS(rand io.Reader, digest []byte) (r, s *big.Int, err error) {
	return SignDigestRS(rand, priv, digest)
}

//摘要签名,返回DER编码的签名
func (priv *PrivateKey) SignDigest(rand io.Reader, digest []byte) ([]byte, error) {
	return SignDigest(rand, priv, digest)
}

//SM2签名摘要算法实现，需要公钥与userid参与计算
func (pub *PublicKey) SM3Digest(msg, uid []byte) ([]byte, error) {
	if uid == nil {
		uid = sm2SignDefaultUserId
	}
	digest := sm3.New()
	z := z(digest, pub, uid)
	digest.Reset()
	digest.Write(z)
	digest.Write(msg)
	return digest.Sum(nil), nil
}

func (pub *PublicKey) Verify(in, uid, signature []byte) bool {
	r, s, err := UnmarshalSign(signature)
	if err != nil {
		return false
	}
	return VerifyRS(pub, uid, in, r, s)
}

func (pub *PublicKey) VerifyRS(in, uid []byte, r, s *big.Int) bool {
	return VerifyRS(pub, uid, in, r, s)
}

func (pub *PublicKey) VerifyDigest(in, signature []byte) bool {
	r, s, err := UnmarshalSign(signature)
	if err != nil {
		return false
	}
	return VerifyDigestRS(pub, in, r, s)
}

func (pub *PublicKey) VerifyDigestRS(in []byte, r, s *big.Int) bool {
	return VerifyDigestRS(pub, in, r, s)
}

//Z = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func z(digest hash.Hash, pub *PublicKey, uid []byte) []byte {
	digest.Reset()
	userIdLen := uint16(len(uid) * 8)
	digest.Write([]byte{byte((userIdLen >> 8) & 0xFF)})
	digest.Write([]byte{byte(userIdLen & 0xFF)})
	if uid != nil && len(uid) > 0 {
		digest.Write(uid)
	}
	digest.Write(appendBigIntTo32Bytes(GetSm2P256V1().A))
	digest.Write(appendBigIntTo32Bytes(pub.Curve.Params().B))
	digest.Write(appendBigIntTo32Bytes(pub.Curve.Params().Gx))
	digest.Write(appendBigIntTo32Bytes(pub.Curve.Params().Gy))
	digest.Write(appendBigIntTo32Bytes(pub.X))
	digest.Write(appendBigIntTo32Bytes(pub.Y))
	return digest.Sum(nil)
}

func appendBigIntTo32Bytes(bn *big.Int) []byte {
	buf := bn.Bytes()
	if n := len(buf); n < 32 {
		buf = append(make([]byte, 32-n), buf...)
	}
	return buf
}

func MarshalSign(r, s *big.Int) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

func UnmarshalSign(sig []byte) (r, s *big.Int, err error) {
	var (
		rx, sx = &big.Int{}, &big.Int{}
		inner  cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(rx) ||
		!inner.ReadASN1Integer(sx) ||
		!inner.Empty() {
		return nil, nil, errors.New("not sm2 sign")
	}
	return rx, sx, nil
}

//netx k
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

//原文裸签,返回DER编码的签名
func Sign(rand io.Reader, priv *PrivateKey, in, uid []byte) ([]byte, error) {
	r, s, err := SignRS(rand, priv, in, uid)
	if err != nil {
		return nil, err
	}
	return MarshalSign(r, s)
}

//原文裸签，返回R||S
func SignRS(rand io.Reader, priv *PrivateKey, in, userId []byte) (r, s *big.Int, err error) {
	hash, err := priv.PublicKey.SM3Digest(in, userId)
	return SignDigestRS(rand, priv, hash)
}

//摘要签名,返回DER编码的签名
func SignDigest(rand io.Reader, priv *PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := SignDigestRS(rand, priv, digest)
	if err != nil {
		return nil, err
	}
	return MarshalSign(r, s)
}

//摘要签名，返回R||S
func SignDigestRS(rand io.Reader, priv *PrivateKey, digest []byte) (r, s *big.Int, err error) {
	//将摘要信息变成大数e
	e := new(big.Int).SetBytes(digest)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	for {
		var k *big.Int
		var err error
		for {
			//生成一个随机数k,1 < k < N -1
			k, err = randFieldElement(c, rand)
			if err != nil {
				return nil, nil, err
			}
			//计算椭圆曲线点(x, y) = k * G
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			//计算r = （e + x）mod n
			r.Add(e, r)
			r.Mod(r, N)
			//若r=0或者r+k=n,则重新小循环,否则就结束小循环
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}
		}
		//乘法逆元和取模函数计算s = ((1+d)^(-1) * (k - r*d)) mod n
		rD := new(big.Int).Mul(r, priv.D)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		//若s = 0 则继续循环
		if s.Sign() != 0 {
			break
		}
	}
	return r, s, nil
}

//签名验证（原文）
func Verify(pub *PublicKey, in, uid, signature []byte) bool {
	r, s, err := UnmarshalSign(signature)
	if err != nil {
		return false
	}

	return VerifyRS(pub, in, uid, r, s)
}

func VerifyRS(pub *PublicKey, in, uid []byte, r, s *big.Int) bool {
	if r.Cmp(one) == -1 || r.Cmp(pub.Curve.Params().N) >= 0 {
		return false
	}
	if s.Cmp(one) == -1 || s.Cmp(pub.Curve.Params().N) >= 0 {
		return false
	}

	hash, err := pub.SM3Digest(in, uid)
	if err != nil {
		return false
	}
	//将摘要信息变成大数e
	e := new(big.Int).SetBytes(hash)
	t := new(big.Int).Add(r, s)
	t.Mod(t, pub.Curve.Params().N)
	if t.Sign() == 0 {
		return false
	}

	x1, y1 := pub.Curve.ScalarBaseMult(s.Bytes())
	x2, y2 := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, y := pub.Curve.Add(x1, y1, x2, y2)
	if x.Sign() == 0 || y.Sign() == 0 {
		return false
	}
	x.Add(x, e)
	x.Mod(x, pub.Curve.Params().N)
	return x.Cmp(r) == 0
}

func VerifyDigest(pub *PublicKey, in, signature []byte) bool {
	r, s, err := UnmarshalSign(signature)
	if err != nil {
		return false
	}
	return VerifyDigestRS(pub, in, r, s)
}

func VerifyDigestRS(pub *PublicKey, digest []byte, r, s *big.Int) bool {
	if r.Cmp(one) == -1 || r.Cmp(pub.Curve.Params().N) >= 0 {
		return false
	}
	if s.Cmp(one) == -1 || s.Cmp(pub.Curve.Params().N) >= 0 {
		return false
	}
	//将摘要信息变成大数e
	e := new(big.Int).SetBytes(digest)
	t := new(big.Int).Add(r, s)
	t.Mod(t, pub.Curve.Params().N)
	if t.Sign() == 0 {
		return false
	}

	x1, y1 := pub.Curve.ScalarBaseMult(s.Bytes())
	x2, y2 := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, y := pub.Curve.Add(x1, y1, x2, y2)
	if x.Sign() == 0 || y.Sign() == 0 {
		return false
	}
	x.Add(x, e)
	x.Mod(x, pub.Curve.Params().N)
	return x.Cmp(r) == 0
}
