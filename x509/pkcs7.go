package x509

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/mmdet/mcrypto/sm2"
	"github.com/mmdet/mcrypto/sm3"
	"math/big"
	"sort"
	"time"
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	Certificates []*Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.156.10197.6.1.4.2.1), Signed Data (1.2.156.10197.6.1.4.2.2),
// and Enveloped Data are supported (1.2.156.10197.6.1.4.2.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

var (
	oidGMPKCS7Data            = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2}
	oidGMData                 = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
	oidGMSignedData           = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type rawCertificates struct {
	Raw asn1.RawContent
}
type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

func (raw rawCertificates) Parse() ([]*Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return ParseCertificates(val.Bytes)
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(encodedAttributes, &raw)
	if err != nil {
		return nil, err
	}
	return raw.Bytes, nil
}

var (
	oidDigestAlgorithmSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestAlgorithmSM3     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
	oidEncryptionAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEncryptionAlgorithmSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}
)

func getCertFromCertsByIssuerAndSerial(certs []*Certificate, ias issuerAndSerial) *Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

func isCertMatchForIssuerAndSerial(cert *Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Compare(cert.RawIssuer, ias.IssuerName.FullBytes) == 0
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes []Attribute
}

// NewSignedData initializes a SignedData with content
func NewSignedData(signerCertificate *Certificate, signerPrivateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}

	ci := contentInfo{
		ContentType: oidGMData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}

	digAlg := pkix.AlgorithmIdentifier{
		Algorithm: oidDigestAlgorithmSM3,
	}
	certs := []*Certificate{signerCertificate}

	si, err := getSignerInfoWithAttr(signerCertificate, signerPrivateKey, data, SignerInfoConfig{})

	sd := signedData{
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digAlg},
		ContentInfo:                ci,
		Certificates:               marshalCertificates(certs),
		CRLs:                       []pkix.CertificateList{},
		SignerInfos:                []signerInfo{si},
	}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: oidGMSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

func getSignerInfoWithAttr(cert *Certificate, pkey crypto.PrivateKey, in []byte, config SignerInfoConfig) (signerInfo, error) {
	h := sm3.New()
	h.Write(in)
	messageDigest := h.Sum(nil)
	attrs := &attributes{}
	attrs.Add(oidAttributeContentType, oidGMData)
	attrs.Add(oidAttributeMessageDigest, messageDigest)
	attrs.Add(oidAttributeSigningTime, time.Now())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshaling()
	if err != nil {
		return signerInfo{}, err
	}
	signature, err := signAttributes(finalAttrs, pkey)
	if err != nil {
		return signerInfo{}, err
	}

	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		return signerInfo{}, err
	}
	signer := signerInfo{
		Version:                   1,
		IssuerAndSerialNumber:     ias,
		AuthenticatedAttributes:   finalAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestAlgorithmSM3},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSASM2},
		EncryptedDigest:           signature,
	}
	return signer, nil
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshaling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}

func cert2issuerAndSerial(cert *Certificate) (issuerAndSerial, error) {
	var ias issuerAndSerial
	// The issuer RDNSequence has to match exactly the sequence in the certificate
	// We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber

	return ias, nil
}

// signs the DER encoded form of the attributes with the private key
func signAttributes(attrs []attribute, pkey crypto.PrivateKey) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	switch priv := pkey.(type) {
	case *sm2.PrivateKey:
		return sm2.Sign(rand.Reader, priv, attrBytes, nil)
	}
	return nil, errors.New("unsupport algop")
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*Certificate) rawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

func ParsePKCS7(data []byte) (p7 *PKCS7, err error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	var info contentInfo
	rest, err := asn1.Unmarshal(data, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}

	if err != nil {
		return
	}

	// fmt.Printf("--> Content Type: %s", info.ContentType)
	switch {
	case info.ContentType.Equal(oidGMSignedData):
		return parseSignedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

type unsignedData []byte

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}
	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
			return nil, err
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

// Verify checks the signatures of a PKCS7 object
// WARNING: Verify does not check signing time or verify certificate chains at
// this time.
func (p7 *PKCS7) Verify() (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer); err != nil {
			return err
		}
	}
	return nil
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

func verifySignature(p7 *PKCS7, signer signerInfo) error {
	//签名原文
	signedData := p7.Content
	//hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	//if err != nil {
	//	return err
	//}
	// fmt.Println("===== hash algo=====:", hash)
	if len(signer.AuthenticatedAttributes) > 0 {
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		h := sm3.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if !hmac.Equal(digest, computed) {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
	}
	cert := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if cert == nil {
		return errors.New("pkcs7: No certificate for signer")
	}

	//algo := getSignatureAlgorithmByHash(hash, signer.DigestEncryptionAlgorithm.Algorithm)
	//if algo == UnknownSignatureAlgorithm {
	//	return ErrPKCS7UnsupportedAlgorithm
	//}
	return cert.CheckSignature(SM2WithSM3, signedData, signer.EncryptedDigest)
}
