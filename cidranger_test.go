package cidranger

import (
	"encoding/json"
	iptrie "github.com/yl2chen/cidranger/iptire"
	"io/ioutil"
	"math/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	rnet "github.com/yl2chen/cidranger/net"
	"go4.org/netipx"
)

/*
 ******************************************************************
 Test Contains/ContainingNetworks against basic brute force ranger.
 ******************************************************************
*/

func TestContainsAgainstBaseIPv4(t *testing.T) {
	testContainsAgainstBase(t, 100000, randIPv4Gen)
}

func TestContainingNetworksAgaistBaseIPv4(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, randIPv4Gen)
}

func TestCoveredNetworksAgainstBaseIPv4(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV4AWSRangesIPNets))
}

// IPv6 spans an extremely large address space (2^128), randomly generated IPs
// will often fall outside of the test ranges (AWS public CIDR blocks), so it
// it more meaningful for testing to run from a curated list of IPv6 IPs.
func TestContainsAgaistBaseIPv6(t *testing.T) {
	testContainsAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestContainingNetworksAgaistBaseIPv6(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestCoveredNetworksAgainstBaseIPv6(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV6AWSRangesIPNets))
}

func testContainsAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	trie := iptrie.NewTrie()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)
	configureTrieWithAWSRanges(t, trie)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		expected, err := baseRanger.Contains(nn.ToIP())
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.Contains(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		}
		addr, ok := netip.AddrFromSlice(nn.ToIP())
		if !ok {
			t.Errorf("netip addr convert fail")
			continue
		}
		got := trie.Find(addr)
		var gotvalue bool
		if got != nil {
			gotvalue = true
		}
		assert.Equal(t, expected, gotvalue)
	}
}

func testNormalizePrefix(pfx netip.Prefix) netip.Prefix {
	if pfx.Addr().Is4() {
		pfx = netip.PrefixFrom(netip.AddrFrom16(pfx.Addr().As16()), pfx.Bits()+96)
	}
	return pfx.Masked()
}

func testContainingNetworksAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	trie := iptrie.NewTrie()

	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)
	configureTrieWithAWSRanges(t, trie)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		expected, err := baseRanger.ContainingNetworks(nn.ToIP())
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.ContainingNetworks(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}

		addr, ok := netip.AddrFromSlice(nn.ToIP())
		if !ok {
			t.Errorf("netip addr convert fail")
			continue
		}
		got := trie.ContainingNetworks(addr)
		assert.Equal(t, len(expected), len(got))
		builderExpected := new(netipx.IPSetBuilder)
		builderGot := new(netipx.IPSetBuilder)

		for _, p := range expected {
			n := p.Network()
			prefix, ok := netipx.FromStdIPNet(&n)
			if !ok {
				t.Errorf("netip addr convert fail")
			}
			builderExpected.AddPrefix(testNormalizePrefix(prefix))
		}
		expSet, err := builderExpected.IPSet()

		for _, g := range got {
			builderGot.AddPrefix(g)
		}
		gotSet, err := builderGot.IPSet()

		if !expSet.Equal(gotSet) {
			t.Errorf("not same set")
		}
	}
}

func testCoversNetworksAgainstBase(t *testing.T, iterations int, netGen networkGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	trie := iptrie.NewTrie()

	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)
	configureTrieWithAWSRanges(t, trie)

	for i := 0; i < iterations; i++ {
		network := netGen()
		expected, err := baseRanger.CoveredNetworks(network.IPNet)
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.CoveredNetworks(network.IPNet)
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}

		queryPrefix, ok := netipx.FromStdIPNet(&network.IPNet)
		if !ok {
			t.Errorf("netip addr convert fail")
		}

		got := trie.CoveredNetworks(queryPrefix)
		assert.Equal(t, len(expected), len(got))
		builderExpected := new(netipx.IPSetBuilder)
		builderGot := new(netipx.IPSetBuilder)

		for _, p := range expected {
			n := p.Network()
			prefix, ok := netipx.FromStdIPNet(&n)
			if !ok {
				t.Errorf("netip addr convert fail")
			}
			builderExpected.AddPrefix(testNormalizePrefix(prefix))
		}
		expSet, err := builderExpected.IPSet()

		for _, g := range got {
			builderGot.AddPrefix(g)
		}
		gotSet, err := builderGot.IPSet()

		if !expSet.Equal(gotSet) {
			t.Errorf("not same set")
		}
	}
}

/*
 ******************************************************************
 Benchmarks.
 ******************************************************************
*/

func BenchmarkPCTrieHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewPCTrieRanger())
}

func BenchmarkTrieHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainsUsingAWSRanges(b, netip.MustParseAddr("52.95.110.1"), iptrie.NewTrie())
}

func BenchmarkPCTrieHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewPCTrieRanger())
}

func BenchmarkTrieHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainsUsingAWSRanges(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"), iptrie.NewTrie())
}

func BenchmarkPCTrieMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewPCTrieRanger())
}

func BenchmarkTrieMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainsUsingAWSRanges(b, netip.MustParseAddr("123.123.123.123"), iptrie.NewTrie())
}

func BenchmarkPCTrieHMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewPCTrieRanger())
}

func BenchmarkTrieHMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainsUsingAWSRanges(b, netip.MustParseAddr("2620::ffff"), iptrie.NewTrie())
}

func BenchmarkPCTrieHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewPCTrieRanger())
}

func BenchmarkTrieHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("52.95.110.1"), iptrie.NewTrie())
}

func BenchmarkPCTrieHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewPCTrieRanger())
}

func BenchmarkTrieHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"), iptrie.NewTrie())
}

func BenchmarkPCTrieMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewPCTrieRanger())
}

func BenchmarkTrieMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("123.123.123.123"), iptrie.NewTrie())
}

func BenchmarkPCTrieHMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewPCTrieRanger())
}

func BenchmarkTrieHMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkTrieContainingNetworksUsingAWSRanges(b, netip.MustParseAddr("2620::ffff"), iptrie.NewTrie())
}

func BenchmarkNewPathprefixTriev4(b *testing.B) {
	benchmarkNewPathprefixTrie(b, "192.128.0.0/24")
}

func BenchmarkNewPathprefixTriev6(b *testing.B) {
	benchmarkNewPathprefixTrie(b, "8000::/24")
}

func benchmarkContainsUsingAWSRanges(tb testing.TB, nn net.IP, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.Contains(nn)
	}
}

func benchmarkContainingNetworksUsingAWSRanges(tb testing.TB, nn net.IP, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.ContainingNetworks(nn)
	}
}

func benchmarkNewPathprefixTrie(b *testing.B, net1 string) {
	_, ipNet1, _ := net.ParseCIDR(net1)
	ones, _ := ipNet1.Mask.Size()

	n1 := rnet.NewNetwork(*ipNet1)
	uOnes := uint(ones)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		newPathprefixTrie(n1, uOnes)
	}
}

func benchmarkTrieContainsUsingAWSRanges(tb testing.TB, nn netip.Addr, trie *iptrie.Trie) {
	configureTrieWithAWSRanges(tb, trie)
	for n := 0; n < tb.(*testing.B).N; n++ {
		trie.Find(nn)
	}
}

func benchmarkTrieContainingNetworksUsingAWSRanges(tb testing.TB, nn netip.Addr, trie *iptrie.Trie) {
	configureTrieWithAWSRanges(tb, trie)
	for n := 0; n < tb.(*testing.B).N; n++ {
		trie.ContainingNetworks(nn)
	}
}

/*
 ******************************************************************
 Helper methods and initialization.
 ******************************************************************
*/

type ipGenerator func() rnet.NetworkNumber

func randIPv4Gen() rnet.NetworkNumber {
	return rnet.NetworkNumber{rand.Uint32()}
}
func randIPv6Gen() rnet.NetworkNumber {
	return rnet.NetworkNumber{rand.Uint32(), rand.Uint32(), rand.Uint32(), rand.Uint32()}
}
func curatedAWSIPv6Gen() rnet.NetworkNumber {
	randIdx := rand.Intn(len(ipV6AWSRangesIPNets))

	// Randomly generate an IP somewhat near the range.
	network := ipV6AWSRangesIPNets[randIdx]
	nn := rnet.NewNetworkNumber(network.IP)
	ones, bits := network.Mask.Size()
	zeros := bits - ones
	nnPartIdx := zeros / rnet.BitsPerUint32
	nn[nnPartIdx] = rand.Uint32()
	return nn
}

type networkGenerator func() rnet.Network

func randomIPNetGenFactory(pool []*net.IPNet) networkGenerator {
	return func() rnet.Network {
		return rnet.NewNetwork(*pool[rand.Intn(len(pool))])
	}
}

type AWSRanges struct {
	Prefixes     []Prefix     `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type IPv6Prefix struct {
	IPPrefix string `json:"ipv6_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

var awsRanges *AWSRanges
var ipV4AWSRangesIPNets []*net.IPNet
var ipV6AWSRangesIPNets []*net.IPNet

func loadAWSRanges() *AWSRanges {
	file, err := ioutil.ReadFile("./testdata/aws_ip_ranges.json")
	if err != nil {
		panic(err)
	}
	var ranges AWSRanges
	err = json.Unmarshal(file, &ranges)
	if err != nil {
		panic(err)
	}
	return &ranges
}

func configureRangerWithAWSRanges(tb testing.TB, ranger Ranger) {
	for _, prefix := range awsRanges.Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(NewBasicRangerEntry(*network))
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(NewBasicRangerEntry(*network))
	}
}

func configureTrieWithAWSRanges(tb testing.TB, trie *iptrie.Trie) {
	for _, prefix := range awsRanges.Prefixes {
		network, err := netip.ParsePrefix(prefix.IPPrefix)
		assert.NoError(tb, err)
		trie.Insert(network, struct{}{})
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		network, err := netip.ParsePrefix(prefix.IPPrefix)
		assert.NoError(tb, err)
		trie.Insert(network, struct{}{})
	}
}

func init() {
	awsRanges = loadAWSRanges()
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV6AWSRangesIPNets = append(ipV6AWSRangesIPNets, network)
	}
	for _, prefix := range awsRanges.Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV4AWSRangesIPNets = append(ipV4AWSRangesIPNets, network)
	}
	rand.Seed(time.Now().Unix())
}
