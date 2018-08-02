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
	"errors"
	"fmt"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

//There is an HsmWallet for every PKCS11 slot
type HsmWallet struct {
	c     *Crypto
	slot  uint
	label string
}

var ErrHsmPINNeeded = errors.New("hsm: partition password needed")

func NewHsmWallet(c *Crypto, slot uint, label string) *HsmWallet {
	return &HsmWallet{c: c, slot: slot, label: label}
}

//URL returns the url for the wallet based on the token label of the partition
func (w *HsmWallet) URL() accounts.URL {
	url := &accounts.URL{Scheme: "hsm", Path: w.label}
	return *url
}

// Status returns "Open" is the application is a logged into the slot for the
// wallet and "Closed" if not logged in.  Otherwise "Error" if unable to get the status.
func (w *HsmWallet) Status() (string, error) {
	isLoggedIn, err := w.c.IsLoggedIn(w.slot)
	if err != nil {
		return "Error", err
	}
	if isLoggedIn {
		return "Open", nil
	} else {
		return "Closed", nil
	}
}

// Open logs into the wallet's slot.
func (w *HsmWallet) Open(passphrase string) error {
	log.Info("Opening Hsm wallet", "url", w.URL())
	if passphrase == "" {
		return ErrHsmPINNeeded
	}
	err := w.c.Login(w.slot, passphrase)
	if err != nil {
		return err
	}
	return nil
}

// Close logs out of the wallet's slot.
func (w *HsmWallet) Close() error {
	log.Info("Closing Hsm wallet", "url", w.URL())
	return w.c.Logout(w.slot)
}

//Accounts returns the list of key addresses.
func (w *HsmWallet) Accounts() []accounts.Account {
	as := make([]accounts.Account, 0)
	addresses, err := w.c.GetAddresses(w.slot)
	if err != nil {
		log.Error("Unable to get addresses.", "err", err)
	}
	for _, a := range addresses {
		var account accounts.Account
		account.Address = a
		account.URL = accounts.URL{Scheme: "hsm", Path: fmt.Sprintf("%s/%s", w.label, strings.ToLower(a.Hex()))}
		as = append(as, account)
	}
	return as
}

//Contains determines if the key pair for the given address is present in the partition.
func (w *HsmWallet) Contains(account accounts.Account) bool {
	contains, err := w.c.ContainsAddress(w.slot, account.Address)
	if err != nil {
		log.Error("Unable to check if wallet contains address.", "err", err)
		return false
	}
	return contains
}

//Derive is not implemented.
func (w *HsmWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	var a accounts.Account
	return a, accounts.ErrNotSupported
}

//SelfDerive is not implemented.
func (w *HsmWallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {

}

//NewHsmAccount generates an ECDSA key pair and returns the account.
func (w *HsmWallet) NewHsmAccount() (accounts.Account, error) {
	a, err := w.c.GenerateECKeyPair(w.slot)
	if err != nil {
		return accounts.Account{}, err
	}
	path := fmt.Sprintf("%s/%s", w.label, strings.ToLower(a.Hex()))
	url := accounts.URL{Scheme: "hsm", Path: path}
	account := accounts.Account{Address: a, URL: url}
	log.Info("Created new Hsm account", "address", account.Address.Hex())
	return account, nil
}

//DeleteAccount deletes the key pair for the given account.
func (w *HsmWallet) DeleteAccount(account accounts.Account) error {
	err := w.c.DeleteAccount(w.slot, account.Address)
	return err
}

//SignHash signs the given hash using the private key for the given account.
func (w *HsmWallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	log.Info("Sighing hash with Hsm", "address", account.Address.Hex())
	sig, err := w.c.Sign(w.slot, hash, account.Address)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

//SignTx signs the given transaction for the given account.
func (w *HsmWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	log.Info("Signing transaction with Hsm", "address", account.Address.Hex())
	var signer types.Signer
	if chainID != nil {
		signer = types.NewEIP155Signer(chainID)
	} else {
		signer = types.HomesteadSigner{}
	}
	h := signer.Hash(tx)
	sig, err := w.c.Sign(w.slot, h[:], account.Address)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(signer, sig)
}

//SignHashWithPassphrase signs the hash.
func (w *HsmWallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return w.SignHash(account, hash)
}

//SignTxWithPassphrase signs the transaction.
func (w *HsmWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.SignTx(account, tx, chainID)
}
