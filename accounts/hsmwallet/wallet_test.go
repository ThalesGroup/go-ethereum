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
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const PIN = "userpin"

const PKCS11_LIBRARY = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"

//const PKCS11_LIBRARY = "/usr/safenet/lunaclient/lib/libcklog2.so"

var (
	wallet  *HsmWallet
	account accounts.Account
	tempDir string
)

func Setup() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
	log.Info("Setup")
	backend, _ := NewHsmBackend(PKCS11_LIBRARY)
	wallet = backend.Wallets()[0].(*HsmWallet)
	wallet.Open(PIN)
	deleteAllAccounts()
}

func Teardown() {
	log.Info("Teardown")
	deleteAllAccounts()
	wallet.Close()
}

func deleteAllAccounts() error {
	accounts := wallet.Accounts()
	for _, account := range accounts {
		err := wallet.DeleteAccount(account)
		if err != nil {
			return err
		}
	}
	return nil
}

func TestNewWalletAccount(t *testing.T) {
	err := deleteAllAccounts()
	if err != nil {
		t.Fatal(err)
	}
	account, err = wallet.NewHsmAccount()
	if err != nil {
		t.Fatal(err)
	}
	as := wallet.Accounts()
	if len(as) != 1 {
		t.Errorf("There should only be 1 account in wallet, found: %d", len(as))
	}
	if as[0] != account {
		t.Errorf("Account (%s, %s) was created but in accounts list was (%s, %s).", account.URL, account.Address.Hex(), as[0].URL, as[0].Address.Hex())
	}
}

func TestListAccounts(t *testing.T) {
	err := deleteAllAccounts()
	if err != nil {
		t.Fatal(err)
	}
	a1, err := wallet.NewHsmAccount()
	if err != nil {
		t.Fatal(err)
	}
	as := wallet.Accounts()
	if len(as) != 1 {
		t.Errorf("There should be 1 account in wallet, found: %d", len(as))
	}
	if as[0] != a1 {
		t.Errorf("Account (%s, %s) was created but in accounts list was (%s, %s).", a1.URL, a1.Address.Hex(), as[0].URL, as[0].Address.Hex())
	}
	time.Sleep(2 * time.Second)
	a2, err := wallet.NewHsmAccount()
	if err != nil {
		t.Fatal(err)
	}
	as = wallet.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 2 {
		t.Errorf("There should be 2 accounts in wallet, found: %d", len(as))
	}
	if as[0] != a1 {
		t.Errorf("Account (%s, %s) was created but in accounts list was (%s, %s).", a1.URL, a1.Address.Hex(), as[0].URL, as[0].Address.Hex())
	}
	if as[1] != a2 {
		t.Errorf("Account (%s, %s) was created but in accounts list was (%s, %s).", a2.URL, a2.Address.Hex(), as[1].URL, as[1].Address.Hex())
	}
}

func TestSignTransaction(t *testing.T) {
	err := deleteAllAccounts()
	if err != nil {
		t.Fatal(err)
	}
	account, err = wallet.NewHsmAccount()
	if err != nil {
		t.Fatal(err)
	}
	addr := account.Address
	chainID := new(big.Int).SetUint64(1)
	tx := types.NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil)
	tx, err = wallet.SignTx(account, tx, chainID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = types.Sender(types.NewEIP155Signer(chainID), tx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		tx, err = wallet.SignTx(account, tx, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = types.Sender(types.HomesteadSigner{}, tx)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestListKeysWalletClosed(t *testing.T) {
	err := deleteAllAccounts()
	if err != nil {
		t.Fatal(err)
	}
	a1, err := wallet.NewHsmAccount()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	a2, err := wallet.NewHsmAccount()
	if err != nil {
		t.Fatal(err)
	}
	wallet.Close()
	defer wallet.Open(PIN)
	as := wallet.Accounts()
	if as[0] != a1 || as[1] != a2 || len(as) != 2 {
		t.Errorf("Accounts not found when wallets closed")
	}
	if !wallet.Contains(a1) || !wallet.Contains(a2) {
		t.Errorf("Wallet does not contain accounts when closed")
	}
}

func TestMain(m *testing.M) {
	Setup()
	retCode := m.Run()
	Teardown()
	os.Exit(retCode)
}
