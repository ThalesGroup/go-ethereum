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
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

//There is an HsmWallet for every PKCS11 slot
type HsmWallet struct {
	backend   *HsmBackend
	c         *Crypto
	slot      uint
	label     string
	bip32     bool
	stateLock sync.RWMutex
	accounts  []accounts.Account
	paths     map[common.Address]accounts.DerivationPath

	deriveRequests []chan chan struct{} //used for signalling to the selfDerive go routine
	deriveQuits    []chan chan struct{}
}

var ErrHsmPINNeeded = errors.New("hsm: partition password needed")

func NewHsmWallet(b *HsmBackend, c *Crypto, slot uint, label string, bip32 bool) *HsmWallet {
	return &HsmWallet{backend: b, c: c, slot: slot, label: label, paths: nil, bip32: bip32}
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
	if w.bip32 {
		err = w.c.DeriveBIP32MasterKeys(w.slot) //Derive the BIP32 master seed and master key pair in the HSM.
		if err != nil {
			return err
		}
	}

	w.stateLock.RLock()
	if w.paths != nil {
		w.stateLock.RUnlock()
		return accounts.ErrWalletAlreadyOpen
	}
	w.stateLock.RUnlock()

	w.stateLock.Lock()
	w.paths = make(map[common.Address]accounts.DerivationPath)
	w.stateLock.Unlock()

	go w.backend.updateFeed.Send(accounts.WalletEvent{Wallet: w, Kind: accounts.WalletOpened})

	return err
}

// Close logs out of the wallet's slot.
func (w *HsmWallet) Close() error {
	log.Info("Closing Hsm wallet", "url", w.URL())

	w.stateLock.Lock()

	w.paths = nil
	w.accounts = nil

	quitcs := make([]chan struct{}, 0)

	for _, deriveQuit := range w.deriveQuits {
		quitc := make(chan struct{}, 1)
		deriveQuit <- quitc
		quitcs = append(quitcs, quitc)
	}
	w.stateLock.Unlock()

	//wait for response from self-derives.
	for _, quitc := range quitcs {
		<-quitc
	}

	w.stateLock.Lock()
	defer w.stateLock.Unlock()
	w.deriveQuits = nil
	w.deriveRequests = nil

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

	w.stateLock.RLock()
	reqcs := make([]chan struct{}, 0)
	if w.deriveRequests != nil {
		for _, deriveRequest := range w.deriveRequests {
			reqc := make(chan struct{}, 1)
			select {
			case deriveRequest <- reqc:
				reqcs = append(reqcs, reqc)
			default:
				// Self-derivation offline, throttled or busy, skip
			}
		}
	}
	w.stateLock.RUnlock() //wait for requests to complete
	for _, reqc := range reqcs {
		<-reqc
	}

	w.stateLock.RLock()
	defer w.stateLock.RUnlock()
	if w.accounts != nil {
		as = append(as, w.accounts...)
	}
	return as
}

//Contains determines if the key pair for the given address is present in the partition.
func (w *HsmWallet) Contains(account accounts.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()
	if w.paths != nil {
		if _, ok := w.paths[account.Address]; ok {
			return true
		}
	}
	contains, err := w.c.ContainsAddress(w.slot, account.Address)
	if err != nil {
		log.Error("Unable to check if wallet contains address.", "err", err)
		return false
	}
	return contains
}

//Derive takes a path to derive a child key using BIP32 and keeps track of the account if pin is true
func (w *HsmWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	if !w.bip32 {
		return accounts.Account{}, errors.New("BIP32 Derivation is disabled.  Set 'NoPKCS11BIP32 = false' in conf [Node] section to enable.")
	}
	address, err := w.c.DeriveBIP32ChildAddress(w.slot, []uint32(path))
	if err != nil {
		return accounts.Account{}, err
	}
	urlPath := fmt.Sprintf("%s/%s", w.label, path)
	url := accounts.URL{Scheme: "hsm", Path: urlPath}
	account := accounts.Account{Address: address, URL: url}
	log.Info("Derived new Hsm account", "path", path, "address", account.Address.Hex())

	if !pin {
		return account, nil
	}
	w.stateLock.Lock()
	defer w.stateLock.Unlock()
	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = path
	}

	return account, nil
}

//SelfDerive derives keys in the background from the base path
func (w *HsmWallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {
	log.Info("Self Derive", "base", base)
	if !w.bip32 {
		log.Info("BIP32 not enabled.  Not performing self-derive.")
		return
	}
	w.stateLock.Lock()

	deriveNextPath := make(accounts.DerivationPath, len(base))
	copy(deriveNextPath[:], base[:])

	deriveNextAddr := common.Address{}

	deriveRequest := make(chan chan struct{})
	w.deriveRequests = append(w.deriveRequests, deriveRequest)
	deriveQuit := make(chan chan struct{})
	w.deriveQuits = append(w.deriveQuits, deriveQuit)

	w.stateLock.Unlock()

	go w.selfDerive(deriveNextPath, deriveNextAddr, chain, deriveRequest, deriveQuit)
	deriveRequest <- make(chan struct{}, 1)
}

func (w *HsmWallet) selfDerive(nextPath accounts.DerivationPath, nextAddr common.Address, deriveChain ethereum.ChainStateReader, deriveReq chan chan struct{}, deriveQuit chan chan struct{}) {

	var (
		accs           []accounts.Account
		paths          []accounts.DerivationPath
		deriveNextAddr common.Address

		context = context.Background()

		quitc chan struct{}
		reqc  chan struct{}
	)
	var err error

	deriveNextAddr = nextAddr

	//signal that the derive has stopped on completion
	//defer close(deriveStopped)

	for quitc == nil {

		select {
		case quitc = <-deriveQuit:
			// Termination requested
			continue
		case reqc = <-deriveReq:
			// Account discovery requested
		}

		var startTime = time.Now()

		for empty := false; !empty; {
			// Retrieve the next derived Ethereum account
			if nextAddr == (common.Address{}) {
				if nextAddr, err = w.c.DeriveBIP32ChildAddress(w.slot, []uint32(nextPath)); err != nil {
					log.Warn("HSM wallet account derivation failed", "err", err)
					break
				}
			}

			// Check the account's status against the current chain state
			var (
				balance *big.Int
				nonce   uint64
			)
			balance, err := deriveChain.BalanceAt(context, nextAddr, nil)
			if err != nil {
				log.Warn("HSM wallet balance retrieval failed", "err", err)
				break
			}
			nonce, err = deriveChain.NonceAt(context, nextAddr, nil)
			if err != nil {
				log.Warn("HSM wallet nonce retrieval failed", "err", err)
				break
			}
			// If the next account is empty, stop self-derivation, but add it nonetheless
			if balance.Sign() == 0 && nonce == 0 {
				empty = true
			}
			// We've just self-derived a new account, start tracking it locally
			path := make(accounts.DerivationPath, len(nextPath))
			copy(path[:], nextPath[:])
			paths = append(paths, path)

			account := accounts.Account{
				Address: nextAddr,
				URL:     accounts.URL{Scheme: "hsm", Path: fmt.Sprintf("%s/%s", w.label, path)},
			}
			accs = append(accs, account)

			// Display a log message to the user for new (or previously empty accounts)
			if _, known := w.paths[nextAddr]; !known || (!empty && nextAddr == deriveNextAddr) {
				log.Info("HSM wallet discovered new account", "address", nextAddr, "path", path, "balance", balance, "nonce", nonce)
			}
			// Fetch the next potential account
			if !empty {
				nextAddr = common.Address{}
				nextPath[len(nextPath)-1]++
			}
			//Check to see if we wallet has been closed and we should stop deriving keys.
			select {
			case quitc = <-deriveQuit:
				quitc <- struct{}{}
				return
			default:
			}

		}

		if nextAddr != deriveNextAddr {
			log.Info("HSM self derivations completed.", "seconds", time.Since(startTime).Seconds())
		}

		// Insert any accounts successfully derived
		w.stateLock.Lock()
		for i := 0; i < len(accs); i++ {
			if _, ok := w.paths[accs[i].Address]; !ok {
				w.accounts = append(w.accounts, accs[i])
				w.paths[accs[i].Address] = paths[i]
			}
		}
		w.stateLock.Unlock()
		reqc <- struct{}{}
		deriveNextAddr = nextAddr
		select {
		case quitc = <-deriveQuit:
			continue
		case <-time.After(time.Second):
			// Waited enough, check the chain again
		}
	}
	quitc <- struct{}{}
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

//SignHash signs the given hash using the private key for the given account.
func (w *HsmWallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	log.Info("Sighing hash with Hsm", "address", account.Address.Hex())

	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	var path = accounts.DerivationPath(nil)
	if p, ok := w.paths[account.Address]; ok {
		path = p
	}

	sig, err := w.c.Sign(w.slot, hash, account.Address, path)
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

	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	var path = accounts.DerivationPath(nil)
	if p, ok := w.paths[account.Address]; ok {
		path = p
	}

	sig, err := w.c.Sign(w.slot, h[:], account.Address, path)
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
