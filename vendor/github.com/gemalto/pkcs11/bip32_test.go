// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

var (
	LIB  = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
	SLOT = uint(0)
	PIN  = "userpin"
)

func loadLib(t *testing.T) *Ctx {
	lib := LIB
	t.Logf("loading %s", lib)
	p := New(lib)
	if p == nil {
		t.Fatal("Failed to init lib")
	}
	return p
}

func setup(t *testing.T) (*Ctx, SessionHandle) {
	p := loadLib(t)
	p.Initialize()
	session, err := p.OpenSession(SLOT, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("open session %s\n", err)
	}
	if err = p.Login(session, CKU_USER, PIN); err != nil {
		t.Fatalf("user pin %s\n", err)
	}
	return p, session
}

func teardown(p *Ctx, session SessionHandle) {
	p.CloseSession(session)
	p.Finalize()
}

func deriveMasterKeyPair(p *Ctx, session SessionHandle, seed ObjectHandle) (ObjectHandle, ObjectHandle, error) {

	publicTemplate := []*Attribute{
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_DERIVE, true),
		NewAttribute(CKA_MODIFIABLE, false),
	}

	privateTemplate := []*Attribute{
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_DERIVE, true),
		NewAttribute(CKA_MODIFIABLE, false),
		NewAttribute(CKA_EXTRACTABLE, false),
	}

	return p.DeriveBIP32MasterKeys(session, seed, publicTemplate, privateTemplate)
}

func deriveChildKeyPair(p *Ctx, session SessionHandle, masterPrivate ObjectHandle, path []uint32) (ObjectHandle, ObjectHandle, uint, error) {

	publicTemplate := []*Attribute{
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_DERIVE, false),
		NewAttribute(CKA_MODIFIABLE, false),
	}

	privateTemplate := []*Attribute{
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_DERIVE, false),
		NewAttribute(CKA_MODIFIABLE, false),
		NewAttribute(CKA_EXTRACTABLE, false),
	}
	return p.DeriveBIP32ChildKeys(session, masterPrivate, publicTemplate, privateTemplate, path)
}

func parsePath(path string) []uint32 {
	path = strings.Replace(path, "m/", "", 1)
	split := strings.Split(path, "/")
	pathUints := make([]uint32, len(split))
	for i, index := range split {
		var x uint32
		if index[len(index)-1] == '\'' {
			x = 0x80000000
			index = strings.TrimRight(index, "'")
		}
		x1, _ := strconv.ParseUint(index, 10, 32)
		x += uint32(x1)
		pathUints[i] = x
	}
	return pathUints
}

func sign(p *Ctx, session SessionHandle, objectHandle ObjectHandle, data []byte) ([]byte, error) {
	err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_ECDSA, nil)}, objectHandle)
	if err != nil {
		return nil, err
	}
	return p.Sign(session, data)
}

func verify(p *Ctx, session SessionHandle, objectHandle ObjectHandle, data []byte, signature []byte) error {
	err := p.VerifyInit(session, []*Mechanism{NewMechanism(CKM_ECDSA, nil)}, objectHandle)
	if err != nil {
		return err
	}
	return p.Verify(session, signature, data)
}

func injectSeed(p *Ctx, session SessionHandle, seed []byte) (ObjectHandle, error) {
	mech := []*Mechanism{NewMechanism(CKM_AES_KEY_GEN, nil)}
	aesTemplate := []*Attribute{
		NewAttribute(CKA_KEY_TYPE, CKK_AES),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_VALUE_LEN, 32),
	}
	wrappingKey, err := p.GenerateKey(session, mech, aesTemplate)
	if err != nil {
		return 0, err
	}

	mech = []*Mechanism{NewMechanism(CKM_AES_CBC, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})}
	err = p.EncryptInit(session, mech, wrappingKey)
	if err != nil {
		return 0, err
	}
	encrypted, err := p.Encrypt(session, seed)
	if err != nil {
		return 0, err
	}

	mech = []*Mechanism{NewMechanism(CKM_AES_CBC, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})}
	seedTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_DERIVE, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_EXTRACTABLE, false),
		NewAttribute(CKA_MODIFIABLE, false),
		NewAttribute(CKA_VALUE_LEN, len(seed)),
	}
	return p.UnwrapKey(session, mech, wrappingKey, encrypted, seedTemplate)
}

func getECPoint(p *Ctx, session SessionHandle, objectHandle ObjectHandle) []byte {
	attributeTemplate := []*Attribute{
		NewAttribute(CKA_EC_POINT, nil),
	}

	attributes, err := p.GetAttributeValue(session, objectHandle, attributeTemplate)
	if err != nil {
		return nil
	}
	return attributes[0].Value
}

func signVerify(t *testing.T, p *Ctx, session SessionHandle, public, private ObjectHandle) {
	message := []byte("message bip32")
	data := sha256.Sum256(message)

	sig, err := sign(p, session, private, data[:])
	if err != nil {
		t.Fatalf("sign %s\n", err)
	}

	err = verify(p, session, public, sig, data[:])
	if err != nil {
		t.Fatalf("verify %s\n", err)
	}
}

func TestBIP32DeriveSignVerify(t *testing.T) {

	p, session := setup(t)
	defer teardown(p, session)

	mech := []*Mechanism{NewMechanism(CKM_GENERIC_SECRET_KEY_GEN, nil)}
	seedTemplate := []*Attribute{
		NewAttribute(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_DERIVE, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_EXTRACTABLE, false),
		NewAttribute(CKA_MODIFIABLE, false),
		NewAttribute(CKA_VALUE_LEN, 32),
	}
	seed, err := p.GenerateKey(session, mech, seedTemplate)
	if err != nil {
		t.Fatalf("master seed %s\n", err)
	}

	_, privateMaster, err := deriveMasterKeyPair(p, session, seed)
	if err != nil {
		t.Fatalf("master key pair %s\n", err)
	}

	path := parsePath("m/44'/60'/0'/0/0")

	publicChild, privateChild, _, err := deriveChildKeyPair(p, session, privateMaster, path)
	if err != nil {
		t.Fatalf("child key pair %s\n", err)
	}

	signVerify(t, p, session, publicChild, privateChild)
}

func TestBIP32VectorInjectDeriveSignVerify(t *testing.T) {
	//https://en.bitcoin.it/wiki/BIP_0032_TestVectors
	vector := [][]string{
		{"000102030405060708090a0b0c0d0e0f", "m/0'", "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"},
		{"000102030405060708090a0b0c0d0e0f", "m/0'/1", "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"},
		{"000102030405060708090a0b0c0d0e0f", "m/0'/1/2'", "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"},
		{"000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2", "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"},
		{"000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"},
		{"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0", "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"},
		{"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'", "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"},
		{"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1", "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"},
		{"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1/2147483646'", "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"},
		{"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1/2147483646'/2", "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"},
	}

	p, session := setup(t)
	defer teardown(p, session)

	for _, v := range vector {
		seed, _ := hex.DecodeString(v[0])
		path := parsePath(v[1])
		public, _ := hex.DecodeString(v[2])
		masterSeed, err := injectSeed(p, session, seed)
		if err != nil {
			t.Fatalf("inject seed %s\n", err)
		}

		_, privateMaster, err := deriveMasterKeyPair(p, session, masterSeed)
		if err != nil {
			t.Fatalf("master key pair %s\n", err)
		}

		publicChild, privateChild, _, err := deriveChildKeyPair(p, session, privateMaster, path)
		if err != nil {
			t.Fatalf("child key pair %s\n", err)
		}

		ecp := getECPoint(p, session, publicChild)
		var ecPoint []byte
		asn1.Unmarshal(ecp, &ecPoint)

		ecPoint = ecPoint[1:33]
		expected := public[1:]
		if bytes.Compare(ecPoint, expected) != 0 {
			t.Fatalf("ecPoint was %s.  Expected %s.", hex.EncodeToString(ecPoint), hex.EncodeToString(expected))
		}

		signVerify(t, p, session, publicChild, privateChild)
	}
}
