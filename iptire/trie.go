// Package iptrie is a fork of github.com/yl2chen/cidranger. This fork massively strips down and refactors the code for
// increased performance, resulting in 20x faster load time, and 1.5x faster lookups.

package iptrie

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
	"unsafe"
)

// Trie is an IP radix trie implementation, similar to what is described
// at https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux
//
// CIDR blocks are stored using a prefix tree structure where each node has its
// parent as prefix, and the path from the root node represents current CIDR
// block.
//
// Path compression compresses a string of node with only 1 child into a single
// node, decrease the amount of lookups necessary during containment tests.
type Trie struct {
	parent   *Trie
	children [2]*Trie

	network netip.Prefix
	value   any
}

// NewTrie creates a new Trie.
func NewTrie() *Trie {
	return &Trie{
		network: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	}
}

func newSubTree(network netip.Prefix, value any) *Trie {
	return &Trie{
		network: network,
		value:   value,
	}
}

// Insert inserts a RangerEntry into prefix trie.
func (p *Trie) Insert(network netip.Prefix, value any) {
	network = normalizePrefix(network)
	p.insert(network, value)
}

// Remove removes RangerEntry identified by given network from trie.
func (p *Trie) Remove(network netip.Prefix) any {
	network = normalizePrefix(network)
	return p.remove(network)
}

// Find returns the value from the smallest prefix containing the given address.
func (p *Trie) Find(ip netip.Addr) any {
	ip = normalizeAddr(ip)
	return p.find(ip)
}

// ContainingNetworks returns the list of RangerEntry(s) the given ip is
// contained in in ascending prefix order.
func (p *Trie) ContainingNetworks(ip netip.Addr) []netip.Prefix {
	ip = normalizeAddr(ip)
	return p.containingNetworks(ip)
}

// CoveredNetworks returns the list of RangerEntry(s) the given ipnet
// covers.  That is, the networks that are completely subsumed by the
// specified network.
func (p *Trie) CoveredNetworks(network netip.Prefix) []netip.Prefix {
	network = normalizePrefix(network)
	return p.coveredNetworks(network)
}

func (p *Trie) Network() netip.Prefix {
	return p.network
}

// String returns string representation of trie, mainly for visualization and
// debugging.
func (p *Trie) String() string {
	children := []string{}
	padding := strings.Repeat("| ", p.level()+1)
	for bit, child := range p.children {
		if child == nil {
			continue
		}
		childStr := fmt.Sprintf("\n%s%d--> %s", padding, bit, child.String())
		children = append(children, childStr)
	}
	return fmt.Sprintf("%s (has_entry:%t)%s", p.network,
		p.value != nil, strings.Join(children, ""))
}

func (p *Trie) find(number netip.Addr) any {
	if !netContains(p.network, number) {
		return nil
	}
	if p.value != nil {
		return p.value
	}
	if p.network.Bits() == 128 {
		return nil
	}
	bit := p.discriminatorBitFromIP(number)
	child := p.children[bit]
	if child != nil {
		return child.find(number)
	}
	return nil
}

func (p *Trie) containingNetworks(addr netip.Addr) []netip.Prefix {
	var results []netip.Prefix
	if !p.network.Contains(addr) {
		return results
	}
	if p.value != nil {
		results = []netip.Prefix{p.network}
	}
	if p.network.Bits() == 128 {
		return results
	}
	bit := p.discriminatorBitFromIP(addr)
	child := p.children[bit]
	if child != nil {
		ranges := child.containingNetworks(addr)
		if len(ranges) > 0 {
			if len(results) > 0 {
				results = append(results, ranges...)
			} else {
				results = ranges
			}
		}
	}
	return results
}

func (p *Trie) coveredNetworks(network netip.Prefix) []netip.Prefix {
	var results []netip.Prefix
	if network.Bits() <= p.network.Bits() && network.Contains(p.network.Addr()) {
		for entry := range p.walkDepth() {
			results = append(results, entry)
		}
	} else if p.network.Bits() < 128 {
		bit := p.discriminatorBitFromIP(network.Addr())
		child := p.children[bit]
		if child != nil {
			return child.coveredNetworks(network)
		}
	}
	return results
}

// This is an unsafe, but faster version of netip.Prefix.Contains
func netContains(pfx netip.Prefix, ip netip.Addr) bool {
	pfxAddr := addr128(pfx.Addr())
	ipAddr := addr128(ip)
	return ipAddr.xor(pfxAddr).and(mask6(pfx.Bits())).isZero()
}

// netDivergence returns the largest prefix shared by the provided 2 prefixes
func netDivergence(net1 netip.Prefix, net2 netip.Prefix) netip.Prefix {
	if net1.Bits() > net2.Bits() {
		net1, net2 = net2, net1
	}

	if netContains(net1, net2.Addr()) {
		return net1
	}

	diff := addr128(net1.Addr()).xor(addr128(net2.Addr()))
	var bit int
	if diff.hi != 0 {
		bit = bits.LeadingZeros64(diff.hi)
	} else {
		bit = bits.LeadingZeros64(diff.lo) + 64
	}
	if bit > net1.Bits() {
		bit = net1.Bits()
	}
	pfx, _ := net1.Addr().Prefix(bit)
	return pfx
}

func (p *Trie) insert(network netip.Prefix, value any) *Trie {
	if p.network == network {
		p.value = value
		return p
	}

	bit := p.discriminatorBitFromIP(network.Addr())
	existingChild := p.children[bit]

	// No existing child, insert new leaf trie.
	if existingChild == nil {
		pNew := newSubTree(network, value)
		p.appendTrie(bit, pNew)
		return pNew
	}

	// Check whether it is necessary to insert additional path prefix between current trie and existing child,
	// in the case that inserted network diverges on its path to existing child.
	netdiv := netDivergence(existingChild.network, network)
	if netdiv != existingChild.network {
		pathPrefix := newSubTree(netdiv, nil)
		p.insertPrefix(bit, pathPrefix, existingChild)
		// Update new child
		existingChild = pathPrefix
	}
	return existingChild.insert(network, value)
}

func (p *Trie) appendTrie(bit uint8, prefix *Trie) {
	p.children[bit] = prefix
	prefix.parent = p
}

func (p *Trie) insertPrefix(bit uint8, pathPrefix, child *Trie) {
	// Set parent/child relationship between current trie and inserted pathPrefix
	p.children[bit] = pathPrefix
	pathPrefix.parent = p

	// Set parent/child relationship between inserted pathPrefix and original child
	pathPrefixBit := pathPrefix.discriminatorBitFromIP(child.network.Addr())
	pathPrefix.children[pathPrefixBit] = child
	child.parent = pathPrefix
}

func (p *Trie) remove(network netip.Prefix) any {
	if p.value != nil && p.network == network {
		entry := p.value
		p.value = nil

		p.compressPathIfPossible()
		return entry
	}
	if p.network.Bits() == 128 {
		return nil
	}
	bit := p.discriminatorBitFromIP(network.Addr())
	child := p.children[bit]
	if child != nil {
		return child.remove(network)
	}
	return nil
}

func (p *Trie) qualifiesForPathCompression() bool {
	// Current prefix trie can be path compressed if it meets all following.
	//		1. records no CIDR entry
	//		2. has single or no child
	//		3. is not root trie
	return p.value == nil && p.childrenCount() <= 1 && p.parent != nil
}

func (p *Trie) compressPathIfPossible() {
	if !p.qualifiesForPathCompression() {
		// Does not qualify to be compressed
		return
	}

	// Find lone child.
	var loneChild *Trie
	for _, child := range p.children {
		if child != nil {
			loneChild = child
			break
		}
	}

	// Find root of currnt single child lineage.
	parent := p.parent
	for ; parent.qualifiesForPathCompression(); parent = parent.parent {
	}
	parentBit := parent.discriminatorBitFromIP(p.network.Addr())
	parent.children[parentBit] = loneChild

	// Attempts to furthur apply path compression at current lineage parent, in case current lineage
	// compressed into parent.
	parent.compressPathIfPossible()
}

func (p *Trie) childrenCount() int {
	count := 0
	for _, child := range p.children {
		if child != nil {
			count++
		}
	}
	return count
}

func (p *Trie) discriminatorBitFromIP(addr netip.Addr) uint8 {
	// This is a safe uint boxing of int since we should never attempt to get
	// target bit at a negative position.
	pos := p.network.Bits()
	a128 := addr128(addr)
	if pos < 64 {
		return uint8(a128.hi >> (63 - pos) & 1)
	}
	return uint8(a128.lo >> (63 - (pos - 64)) & 1)
}

func (p *Trie) level() int {
	if p.parent == nil {
		return 0
	}
	return p.parent.level() + 1
}

// walkDepth walks the trie in depth order, for unit testing.
func (p *Trie) walkDepth() <-chan netip.Prefix {
	entries := make(chan netip.Prefix)
	go func() {
		if p.value != nil {
			entries <- p.network
		}
		childEntriesList := []<-chan netip.Prefix{}
		for _, trie := range p.children {
			if trie == nil {
				continue
			}
			childEntriesList = append(childEntriesList, trie.walkDepth())
		}
		for _, childEntries := range childEntriesList {
			for entry := range childEntries {
				entries <- entry
			}
		}
		close(entries)
	}()
	return entries
}

// TrieLoader can be used to improve the performance of bulk inserts to a Trie. It caches the node of the
// last insert in the tree, using it as the starting point to start searching for the location of the next insert. This
// is highly beneficial when the addresses are pre-sorted.
type TrieLoader struct {
	trie       *Trie
	lastInsert *Trie
}

func NewTrieLoader(trie *Trie) *TrieLoader {
	return &TrieLoader{
		trie:       trie,
		lastInsert: trie,
	}
}

func (ptl *TrieLoader) Insert(pfx netip.Prefix, v any) {
	pfx = normalizePrefix(pfx)

	diff := addr128(ptl.lastInsert.network.Addr()).xor(addr128(pfx.Addr()))
	var pos int
	if diff.hi != 0 {
		pos = bits.LeadingZeros64(diff.hi)
	} else {
		pos = bits.LeadingZeros64(diff.lo) + 64
	}
	if pos > pfx.Bits() {
		pos = pfx.Bits()
	}
	if pos > ptl.lastInsert.network.Bits() {
		pos = ptl.lastInsert.network.Bits()
	}

	parent := ptl.lastInsert
	for parent.network.Bits() > pos {
		parent = parent.parent
	}
	ptl.lastInsert = parent.insert(pfx, v)
}

func normalizeAddr(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return netip.AddrFrom16(addr.As16())
	}
	return addr
}

func normalizePrefix(pfx netip.Prefix) netip.Prefix {
	if pfx.Addr().Is4() {
		pfx = netip.PrefixFrom(netip.AddrFrom16(pfx.Addr().As16()), pfx.Bits()+96)
	}
	return pfx.Masked()
}

func addr128(addr netip.Addr) uint128 {
	return *(*uint128)(unsafe.Pointer(&addr))
}

func init() {
	// Accessing the underlying data of a `netip.Addr` relies upon the data being
	// in a known format, which is not guaranteed to be stable. So this init()
	// function is to detect if it ever changes.
	ip := netip.AddrFrom16([16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	i128 := addr128(ip)
	if i128.hi != 0x0001020304050607 || i128.lo != 0x08090a0b0c0d0e0f {
		panic("netip.Addr format mismatch")
	}
}
