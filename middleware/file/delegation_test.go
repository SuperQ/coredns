package file

import (
	"sort"
	"strings"
	"testing"

	"github.com/miekg/coredns/middleware/pkg/dnsrecorder"
	"github.com/miekg/coredns/middleware/test"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

var delegationTestCases = []test.Case{
	{
		Qname: "a.delegated.miek.nl.", Qtype: dns.TypeTXT,
		Ns: []dns.RR{
			test.NS("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
			test.NS("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		},
		Extra: []dns.RR{
			test.A("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
			test.AAAA("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
		},
	},
	{
		Qname: "delegated.miek.nl.", Qtype: dns.TypeNS,
		Answer: []dns.RR{
			test.NS("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
			test.NS("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		},
	},
	{
		Qname: "foo.delegated.miek.nl.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.NS("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
			test.NS("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		},
		Extra: []dns.RR{
			test.A("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
			test.AAAA("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
		},
	},
	{
		Qname: "foo.delegated.miek.nl.", Qtype: dns.TypeTXT,
		Answer: []dns.RR{
			test.NS("delegated.miek.nl.	1800	IN	NS	a.delegated.miek.nl."),
			test.NS("delegated.miek.nl.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		},
		Extra: []dns.RR{
			test.A("a.delegated.miek.nl. 1800 IN A 139.162.196.78"),
			test.AAAA("a.delegated.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
		},
	},
	{
		Qname: "miek.nl.", Qtype: dns.TypeSOA,
		Answer: []dns.RR{
			test.SOA("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
		},
	},
	{
		Qname: "miek.nl.", Qtype: dns.TypeAAAA,
		Ns: []dns.RR{
			test.SOA("miek.nl.	1800	IN	SOA	linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"),
		},
	},
}

var secureDelegationTestCases = []test.Case{
	{
		Qname: "a.delegated.example.org.", Qtype: dns.TypeTXT,
		Do: true,
		Ns: []dns.RR{
			test.NS("delegated.example.org.	1800	IN	NS	a.delegated.example.org."),
			test.NS("delegated.example.org.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		},
		Extra: []dns.RR{
			test.A("a.delegated.example.org. 1800 IN A 139.162.196.78"),
			test.AAAA("a.delegated.example.org. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
		},
	},
	{
		Qname: "delegated.example.org.", Qtype: dns.TypeNS,
		Do: true,
		Answer: []dns.RR{
			test.NS("delegated.example.org.	1800	IN	NS	a.delegated.example.org."),
			test.NS("delegated.example.org.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		},
	},
	{
		Qname: "foo.delegated.example.org.", Qtype: dns.TypeA,
		Do: true,
		Ns: []dns.RR{
			test.NS("delegated.example.org.	1800	IN	NS	a.delegated.example.org."),
			test.NS("delegated.example.org.	1800	IN	NS	ns-ext.nlnetlabs.nl."),
		},
		Extra: []dns.RR{
			test.A("a.delegated.example.org. 1800 IN A 139.162.196.78"),
			test.AAAA("a.delegated.example.org. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"),
		},
	},
}

func TestLookupDelegation(t *testing.T) {
	testDelegation(t, dbMiekNLDelegation, testzone, delegationTestCases)
}

func TestLookupSecureDelegation(t *testing.T) {
	testDelegation(t, ExampleOrgSigned, "example.org.", secureDelegationTestCases)
}

func testDelegation(t *testing.T, z, origin string, testcases []test.Case) {
	zone, err := Parse(strings.NewReader(z), origin, "stdin")
	if err != nil {
		t.Fatalf("expect no error when reading zone, got %q", err)
	}

	fm := File{Next: test.ErrorHandler(), Zones: Zones{Z: map[string]*Zone{origin: zone}, Names: []string{origin}}}
	ctx := context.TODO()

	for _, tc := range testcases {
		m := tc.Msg()

		rec := dnsrecorder.New(&test.ResponseWriter{})
		_, err := fm.ServeDNS(ctx, rec, m)
		if err != nil {
			t.Errorf("expected no error, got %v\n", err)
			return
		}

		resp := rec.Msg
		sort.Sort(test.RRSet(resp.Answer))
		sort.Sort(test.RRSet(resp.Ns))
		sort.Sort(test.RRSet(resp.Extra))

		if !test.Header(t, tc, resp) {
			t.Logf("%v\n", resp)
			continue
		}
		if !test.Section(t, tc, test.Answer, resp.Answer) {
			t.Logf("%v\n", resp)
		}
		if !test.Section(t, tc, test.Ns, resp.Ns) {
			t.Logf("%v\n", resp)
		}
		if !test.Section(t, tc, test.Extra, resp.Extra) {
			t.Logf("%v\n", resp)
		}
	}
}

const dbMiekNLDelegation = `
$TTL    30M
$ORIGIN miek.nl.
@       IN      SOA     linode.atoom.net. miek.miek.nl. (
                             1282630057 ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             4H )       ; Negative Cache TTL
                IN      NS      linode.atoom.net.
                IN      NS      ns-ext.nlnetlabs.nl.
                IN      NS      omval.tednet.nl.
                IN      NS      ext.ns.whyscream.net.

                IN      MX      1  aspmx.l.google.com.
                IN      MX      5  alt1.aspmx.l.google.com.
                IN      MX      5  alt2.aspmx.l.google.com.
                IN      MX      10 aspmx2.googlemail.com.
                IN      MX      10 aspmx3.googlemail.com.

delegated	IN	NS      a.delegated
		IN	NS      ns-ext.nlnetlabs.nl.

a.delegated     IN      TXT     "obscured"
                IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735

a               IN      A       139.162.196.78
                IN      AAAA    2a01:7e00::f03c:91ff:fef1:6735
www             IN      CNAME   a
archive         IN      CNAME   a`
