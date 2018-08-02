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
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gemalto/pkcs11"
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
	backend, _ := NewHsmBackend(PKCS11_LIBRARY, true)
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
	wallet.Open(PIN)
	accounts := wallet.Accounts()
	for _, account := range accounts {
		err := wallet.c.DeleteAccount(wallet.slot, account.Address)
		if err != nil {
			return err
		}
	}
	wallet.c.DeleteMasterKeys(wallet.slot)
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

func TestDeriveBIP32(t *testing.T) {
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

	for _, v := range vector {

		err := deleteAllAccounts()
		if err != nil {
			t.Fatal(err)
		}
		seed, _ := hex.DecodeString(v[0])
		path, _ := accounts.ParseDerivationPath(v[1])
		public, _ := hex.DecodeString(v[2])

		wallet.c.InjectMasterSeed(wallet.slot, seed)
		wallet.Close()
		wallet.Open(PIN)

		session, err := wallet.c.p.OpenSession(wallet.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			t.Fatal(err)
		}
		defer wallet.c.p.CloseSession(session)
		publicKey, _, err := wallet.c.DeriveBIP32ChildKeys(session, wallet.c.masterPrivateKeys[wallet.slot], path)
		if err != nil {
			t.Fatal(err)
		}
		ecPoint, _ := wallet.c.GetDecodedECPoint(session, *publicKey)
		ecPoint = ecPoint[1:33]
		expected := public[1:]
		if bytes.Compare(ecPoint, expected) != 0 {
			t.Errorf("ecPoint X was %s.  Expected %s.", hex.EncodeToString(ecPoint), hex.EncodeToString(expected))
		}
	}

}

func TestDeriveAndSign(t *testing.T) {
	err := deleteAllAccounts()
	if err != nil {
		t.Fatal(err)
	}
	wallet.Open(PIN)

	path := []uint32{0x80000000 + 44, 0x80000000 + 66, 0x80000000, 0, 0}
	account, err = wallet.Derive(path, true)
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

}

type MockChainReader struct {
}

func (m *MockChainReader) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	if account.Hex() == "0x022b971dFF0C43305e691DEd7a14367AF19D6407" || account.Hex() == "0x50B39456B0BF3D27F50E41ee94e6Afd242f224E7" {
		return big.NewInt(1), nil
	} else {
		return big.NewInt(0), nil
	}

}

func (m *MockChainReader) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	if account.Hex() == "0x022b971dFF0C43305e691DEd7a14367AF19D6407" || account.Hex() == "0x50B39456B0BF3D27F50E41ee94e6Afd242f224E7" {
		return 1, nil
	} else {
		return 0, nil
	}
}

func (m *MockChainReader) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	return nil, nil
}
func (m *MockChainReader) StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	return nil, nil
}

func TestSelfDerive(t *testing.T) {
	err := deleteAllAccounts()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	wallet.c.InjectMasterSeed(wallet.slot, seed)
	wallet.Close()
	wallet.Open(PIN)
	path1, _ := accounts.ParseDerivationPath("m/44'/60'/0'/0/0")
	path2, _ := accounts.ParseDerivationPath("m/44'/60'/0'/1/0")
	chain := new(MockChainReader)
	wallet.SelfDerive(path1, chain)
	wallet.SelfDerive(path2, chain)

	as := wallet.Accounts()
	for len(as) != 4 {
		as = wallet.Accounts()
	}
	addresses := []string{"0x022b971dFF0C43305e691DEd7a14367AF19D6407", "0x50B39456B0BF3D27F50E41ee94e6Afd242f224E7", "0xbb7A182240010703dc81D6b1EFf630CA02a169FD", "0x03ad1F1C41147663f84167437382fd6801b72B4C"}
	for _, address := range addresses {
		found := false
		for _, account := range as {
			if account.Address.Hex() == address {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Did not see derived account for address: %s.", address)
		}
	}
}

func TestMain(m *testing.M) {
	Setup()
	retCode := m.Run()
	Teardown()
	os.Exit(retCode)
}
