// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package hsmwallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/miekg/pkcs11"
)

type Crypto struct {
	p        *pkcs11.Ctx
	sessions map[uint]pkcs11.SessionHandle
}

var (
	halfOrder = new(big.Int).Rsh(crypto.S256().Params().N, 1) //this is used to enforce low s value
)

func NewCrypto(lib string) (*Crypto, error) {
	p := pkcs11.New(lib)
	err := p.Initialize()
	if err != nil {
		return nil, err
	}

	c := &Crypto{p, make(map[uint]pkcs11.SessionHandle)}
	return c, nil
}

//GetTokenLabelSlots returns a map of token labels to slot number.
func (c *Crypto) GetTokenLabelSlots() (map[string]uint, error) {
	log.Debug("Crypto.GetTokenLabelSlots")
	slots, err := c.p.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	tokens := make(map[string]uint)
	for _, s := range slots {
		t, err := c.p.GetTokenInfo(s)
		if err != nil {
			return nil, err
		}
		tokens[t.Label] = s
	}
	return tokens, nil
}

//Login opens a session and logs in and stores the session.
//Other sessions opened will be in a logged in state.
func (c *Crypto) Login(slot uint, password string) error {
	log.Debug("Crypto.Login", "slot", slot)
	session, err := c.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return err
	}
	err = c.p.Login(session, pkcs11.CKU_USER, password)
	if err != nil {
		log.Error("Login failed", "err", err)
		return err
	}
	c.sessions[slot] = session
	return nil
}

//IsLoggedIn checks to see if the slot is in a logged in state.
func (c *Crypto) IsLoggedIn(slot uint) (bool, error) {
	log.Debug("Crypto.IsLoggedIn", "slot", slot)
	session, err := c.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return false, err
	}
	defer c.p.CloseSession(session)
	sessionInfo, err := c.p.GetSessionInfo(session)
	if err != nil {
		log.Error("GetSessionInfo failed", "err", err)
		return false, err
	}
	loggedInState := uint(3) //CKS_RW_USER_FUNCTIONS
	log.Debug("Is logged in", "value", sessionInfo.State == loggedInState)
	return sessionInfo.State == loggedInState, nil
}

//Logout performs a logout operation on the given slot and closes the master session.
func (c *Crypto) Logout(slot uint) error {
	log.Debug("Crypto.Logout", "slot", slot)
	session, err := c.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return err
	}
	masterSession, ok := c.sessions[slot]
	if ok {
		c.p.CloseSession(masterSession)
	}
	defer c.p.CloseSession(session)
	return c.p.Logout(session)
}

//OpenSession opens a session on the given slot.
func (c *Crypto) OpenSession(slot uint) (pkcs11.SessionHandle, error) {
	return c.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
}

type AddressTime struct {
	Address common.Address
	Time    uint64
}

type ByTime []AddressTime

func (a ByTime) Len() int           { return len(a) }
func (a ByTime) Less(i, j int) bool { return a[i].Time < a[j].Time }
func (a ByTime) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByTime) Addresses() []common.Address {
	addresses := make([]common.Address, 0)
	for _, at := range a {
		addresses = append(addresses, at.Address)
	}
	return addresses
}

//GetAddresses returns all of the addresses for the given slot.
func (c *Crypto) GetAddresses(slot uint) ([]common.Address, error) {
	log.Debug("Crypto.GetAddresses", "slot", slot)
	addresses := make([]AddressTime, 0)
	session, err := c.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return nil, err
	}
	defer c.p.CloseSession(session)

	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	//First find the list of all public objects.
	objects, err := c.FindObjects(session, pubKeyTemplate)
	if err != nil {
		log.Error("FindObjects of public keys failed", "err", err)
		return nil, err
	}

	//For each of the public objects, determine the address and check that it matches the label
	for _, o := range objects {
		label, err := c.GetLabel(session, o)
		if err != nil {
			continue
		}
		address, err := c.GetAddressFromPublicKeyHandle(session, o)
		if address.Hex() != label {
			continue
		}
		t, err := c.GetTimeStamp(session, o)
		if err != nil {
			continue
		}
		addresses = append(addresses, AddressTime{address, t})
	}
	sort.Sort(ByTime(addresses))
	return ByTime(addresses).Addresses(), nil
}

//ContainsAddress checks to see if there is a public key for the given address
//in the given slot.  Uses a public session to see objects if not logged in (wallet closed)
func (c *Crypto) ContainsAddress(slot uint, address common.Address) (bool, error) {
	log.Debug("Crypto.GenerateECKeyPair", "slot", slot, "address", address.Hex())
	session, err := c.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return false, err
	}
	defer c.p.CloseSession(session)

	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, address.Hex()),
	}

	object, err := c.FindObject(session, pubKeyTemplate)
	if err != nil {
		return false, err
	}
	if object == nil {
		return false, nil
	}
	return true, nil
}

//GenerateECKeyPair generates an ECDSA key pair, calculates the address and
//sets the label of the keys to the address.
func (c *Crypto) GenerateECKeyPair(slot uint) (common.Address, error) {
	log.Debug("Crypto.GenerateECKeyPair", "slot", slot)
	session, err := c.p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return common.Address{}, err
	}
	defer c.p.CloseSession(session)

	//get a timestamp to set as CKA_ID so keys can be sorted chronologically
	t := time.Now().Unix()
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(t))

	ecParams := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A} //secp256k1

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "EC-public-key"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ts),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "EC-private-key"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ts),
	}

	publicKeyHandle, privateKeyHandle, err := c.p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		return common.Address{}, err
	}

	address, err := c.GetAddressFromPublicKeyHandle(session, publicKeyHandle)
	if err != nil {
		return address, nil
	}

	err = c.SetLabel(session, publicKeyHandle, address.Hex())
	if err != nil {
		return address, err
	}
	err = c.SetLabel(session, privateKeyHandle, address.Hex())
	if err != nil {
		return address, err
	}

	return address, nil
}

//GetECPoint returns the CKA_EC_POINT of the given public key.
func (c *Crypto) GetECPoint(session pkcs11.SessionHandle, publicKeyHandle pkcs11.ObjectHandle) ([]byte, error) {

	log.Debug("Crypto.GetECPoint", "session", session, "publicKeyHandle", publicKeyHandle)

	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attributes, err := c.p.GetAttributeValue(session, publicKeyHandle, attributeTemplate)
	if err != nil {
		return nil, err
	}

	var ecPoint []byte

	for _, attribute := range attributes {
		if attribute.Type == pkcs11.CKA_EC_POINT {
			ecPoint = attribute.Value
			break
		}
	}
	if ecPoint != nil {
		log.Debug("ECPoint found.", "CKA_EC_POINT", hex.EncodeToString(ecPoint))
		return ecPoint, nil
	}
	return nil, errors.New("Unable to get ECPoint")
}

//GetDecodedECPoint decodes the ecpoint and removes the DER encoding.
func (c *Crypto) GetDecodedECPoint(session pkcs11.SessionHandle, publicKeyHandle pkcs11.ObjectHandle) ([]byte, error) {
	ecPoint, err := c.GetECPoint(session, publicKeyHandle)
	if err != nil {
		return nil, err
	}
	var ecp []byte
	_, err = asn1.Unmarshal(ecPoint, &ecp)
	if err != nil {
		log.Error("Failed to decode ASN.1 encoded ECDSA Public Key (CKA_EC_POINT)", "err", err)
		return nil, err
	}
	return ecp, nil
}

//GetAddressFromPublicKeyHandle returns an address for the given public key.
func (c *Crypto) GetAddressFromPublicKeyHandle(session pkcs11.SessionHandle, publicKeyHandle pkcs11.ObjectHandle) (common.Address, error) {

	log.Debug("GetAddressFromPublicKeyHandle", "session", session, "publicKeyHandle", publicKeyHandle)

	var address common.Address
	ecp, err := c.GetDecodedECPoint(session, publicKeyHandle)
	if err != nil {
		return address, err
	}

	log.Debug("Decoded ECPoint.", "ecPoint", hex.EncodeToString(ecp), "len", len(ecp))

	var pubKey ecdsa.PublicKey
	pubKey.Curve = crypto.S256()
	pubKey.X, pubKey.Y = elliptic.Unmarshal(pubKey.Curve, ecp)
	if pubKey.X == nil {
		return address, errors.New("Unable to unmarshal ECPoint.")
	}
	log.Debug("Created PublicKey.", "X", pubKey.X, "Y", pubKey.Y)

	address = crypto.PubkeyToAddress(pubKey)
	log.Debug("Address from public key", "address", address)
	return address, nil
}

//SetLabel sets the label for the given object.
func (c *Crypto) SetLabel(session pkcs11.SessionHandle, objectHandle pkcs11.ObjectHandle, label string) error {
	log.Debug("Crypto.SetLabel", "session", session, "objectHandle", objectHandle, "label", label)
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	return c.p.SetAttributeValue(session, objectHandle, attributeTemplate)
}

//GetLabel returns the label for the given object.
func (c *Crypto) GetLabel(session pkcs11.SessionHandle, objectHandle pkcs11.ObjectHandle) (string, error) {
	log.Debug("Crypto.GetLabel", "session", session, "objectHandle", objectHandle)
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	as, err := c.p.GetAttributeValue(session, objectHandle, attributeTemplate)
	if err != nil {
		return "", err
	}
	return string(as[0].Value), nil
}

//GetTimeStamp gets the timestamp from the CKA_ID attribute.
func (c *Crypto) GetTimeStamp(session pkcs11.SessionHandle, objectHandle pkcs11.ObjectHandle) (uint64, error) {
	log.Debug("Crypto.GetTimeStamp", "session", session, "objectHandle", objectHandle)
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}
	as, err := c.p.GetAttributeValue(session, objectHandle, attributeTemplate)
	if err != nil {
		return 0, err
	}
	if len(as[0].Value) == 8 {
		return binary.BigEndian.Uint64(as[0].Value), nil
	} else {
		return 0, err
	}
}

//FindObjects returns a list of objects for the given attributes template.
func (c *Crypto) FindObjects(session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	err := c.p.FindObjectsInit(session, template)
	if err != nil {
		log.Error("FindObjectsInit failed", "err", err)
		return nil, err
	}
	var done = false
	var objects = make([]pkcs11.ObjectHandle, 0)
	for !done {
		os, more, err := c.p.FindObjects(session, 1000)
		if err != nil {
			log.Error("FindObjects failed", "err", err)
			return nil, err
		}
		objects = append(objects, os...)
		done = !more
	}
	return objects, nil
}

//FindObject returns a aobject for the given attribute template.
func (c *Crypto) FindObject(session pkcs11.SessionHandle, template []*pkcs11.Attribute) (*pkcs11.ObjectHandle, error) {
	err := c.p.FindObjectsInit(session, template)
	if err != nil {
		log.Error("FindObjectsInit failed", "err", err)
		return nil, err
	}

	os, _, err := c.p.FindObjects(session, 1)
	if err != nil {
		log.Error("FindObjects failed", "err", err)
		return nil, err
	}
	if len(os) == 0 {
		return nil, nil
	}
	return &os[0], nil
}

//GetPrivateKeyHandleFromAddress returns the private key object handle for
//the given address.
func (c *Crypto) GetPrivateKeyHandleFromAddress(session pkcs11.SessionHandle, address common.Address) (*pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, address.Hex()),
	}
	return c.FindObject(session, template)
}

//GetDecodedECPointFromAddress returns the decoded EC point for the given address.
func (c *Crypto) GetDecodedECPointFromAddress(session pkcs11.SessionHandle, address common.Address) ([]byte, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, address.Hex()),
	}
	public, err := c.FindObject(session, template)
	if err != nil {
		return nil, err
	}
	if public == nil {
		return nil, errors.New(fmt.Sprintf("Unable to find public key for address: %s", address.Hex()))
	}
	return c.GetDecodedECPoint(session, *public)
}

//SignatureToLowS ensures that the signature has a low S value as Ethereum requires.
func (c *Crypto) SignatureToLowS(sig []byte) ([]byte, error) {
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(sig[0 : len(sig)/2])
	s.SetBytes(sig[len(sig)/2:])
	if s.Cmp(halfOrder) == 1 {
		s.Sub(crypto.S256().Params().N, s)
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	ret := make([]byte, len(sig))
	rOffset := len(sig)/2 - len(rBytes)
	sOffset := len(sig)/2 - len(sBytes)
	copy(ret[rOffset:len(sig)/2], rBytes)
	copy(ret[len(sig)/2+sOffset:], sBytes)
	return ret, nil
}

//Sign returns a signature of the given hash for using the private key
//of the given address.
func (c *Crypto) Sign(slot uint, hash []byte, address common.Address) ([]byte, error) {
	log.Debug("Crypto.Sign", "slot", slot, "hash", hash, "address", address.Hex())
	session, err := c.OpenSession(slot)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return nil, err
	}
	defer c.p.CloseSession(session)
	private, err := c.GetPrivateKeyHandleFromAddress(session, address)
	if err != nil {
		return nil, err
	}
	if private == nil {
		return nil, accounts.ErrUnknownAccount
	}
	err = c.p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, *private)
	if err != nil {
		return nil, err
	}
	sig, err := c.p.Sign(session, hash)
	if err != nil {
		return nil, err
	}
	log.Debug("PKCS11 ECDSA Signature", "sig", hex.EncodeToString(sig), "len", len(sig))

	sig, err = c.SignatureToLowS(sig)
	if err != nil {
		return nil, err
	}

	log.Debug("Signature Low S", "sig", hex.EncodeToString(sig), "len", len(sig))
	//As Ethereum requires it, determining the V value for the signature so that
	//the public key can be recovered from the signature
	sigWithV := make([]byte, 65)
	copy(sigWithV, sig)
	for i := 0; i < 2; i++ {
		sigWithV[64] = byte(i)
		recovered, err := crypto.Ecrecover(hash, sigWithV)
		if err != nil {
			log.Error("EC Recover failed", "err", err)
			continue
		}

		if recovered != nil {
			pubKey, err := crypto.UnmarshalPubkey(recovered)
			if err != nil {
				continue
			}
			recoveredAddr := crypto.PubkeyToAddress(*pubKey)
			if recoveredAddr.Hex() == address.Hex() {
				log.Debug("Signature with recovery.", "sigWithV", hex.EncodeToString(sigWithV))
				return sigWithV, nil
			}
		}
	}
	return nil, errors.New("Unable to find EC recovery value.")
}

//DeleteAccount deletes the key pair for the given address.
func (c *Crypto) DeleteAccount(slot uint, address common.Address) error {
	log.Debug("Crypto.DeleteAccount", "slot", slot, "address", address.Hex())
	session, err := c.OpenSession(slot)
	if err != nil {
		log.Error("OpenSession failed", "err", err)
		return err
	}
	defer c.p.CloseSession(session)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, address.Hex()),
	}
	objects, err := c.FindObjects(session, template)
	if err != nil {
		return err
	}
	for _, object := range objects {
		err = c.p.DestroyObject(session, object)
		if err != nil {
			return err
		}
	}
	return nil
}
