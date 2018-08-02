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
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
)

type HsmBackend struct {
	c *Crypto
}

func NewHsmBackend(lib string) (*HsmBackend, error) {
	c, err := NewCrypto(lib)
	if err != nil {
		return nil, err
	}
	pb := &HsmBackend{c}
	return pb, nil
}

// Wallets returns an HsmWallet for each slot that is seen.
func (h *HsmBackend) Wallets() []accounts.Wallet {
	t, err := h.c.GetTokenLabelSlots()
	if err != nil {
		return make([]accounts.Wallet, 0)
	}
	wallets := make([]accounts.Wallet, 0, len(t))
	for k := range t {
		wallets = append(wallets, NewHsmWallet(h.c, t[k], k))
	}
	return wallets
}

//No support for subscriptons
type HsmSubscription struct {
}

func (s *HsmSubscription) Err() <-chan error {
	return make(chan error)
}

func (s *HsmSubscription) Unsubscribe() {

}

// Subscribe not implemented.
func (p *HsmBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return &HsmSubscription{}
}
