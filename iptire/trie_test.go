package iptrie

import (
	"log"
	"net/netip"
	"testing"
)

func TestFind(t *testing.T) {
	trie := NewTrie[[]string]()
	n1 := netip.MustParsePrefix("8.8.8.0/24")
	trie.Insert(n1, &[]string{"ABC", "DEF"})

	n2 := netip.MustParsePrefix("8.8.8.128/25")
	trie.Insert(n2, &[]string{"ABC", "xyz"})

	e1 := trie.Find(netip.MustParseAddr("8.8.8.130"))
	if e1 == nil {
		t.Errorf("shouldn't be nil")
	}

	for _, a := range *e1.Value {
		log.Printf("%+v\n", a)
	}
}

func TestContainNetwork(t *testing.T) {
	trie := NewTrie[[]string]()
	n1 := netip.MustParsePrefix("8.8.8.0/24")
	trie.Insert(n1, &[]string{"ABC", "DEF"})

	n2 := netip.MustParsePrefix("8.8.8.0/25")
	trie.Insert(n2, &[]string{"ABC", "xyz"})

	ee := trie.ContainingNetworks(netip.MustParseAddr("8.8.8.0"))
	if ee == nil {
		t.Errorf("should find")
	}

	for _, e := range ee {
		for _, a := range *e.Value {
			log.Printf("%+v\n", a)
		}
	}
}

func TestCoveredNetworks(t *testing.T) {
	trie := NewTrie[[]string]()
	n1 := netip.MustParsePrefix("8.8.8.0/24")
	trie.Insert(n1, &[]string{"ABC", "DEF"})

	n2 := netip.MustParsePrefix("8.8.8.0/25")
	trie.Insert(n2, &[]string{"ABC", "xyz"})

	ee := trie.CoveredNetworks(netip.MustParsePrefix("8.8.0.0/16"))
	if ee == nil {
		t.Errorf("should find")
	}

	for _, e := range ee {
		for _, a := range *e.Value {
			log.Printf("%+v\n", a)
		}
	}
}
