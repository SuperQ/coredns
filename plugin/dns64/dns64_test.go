package dns64

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func To6(prefix, address string) (net.IP, error) {
	_, pref, _ := net.ParseCIDR(prefix)
	addr := net.ParseIP(address)

	return to6(pref, addr)
}

func TestTo6(t *testing.T) {

	v6, err := To6("64:ff9b::/96", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:ff9b::4040:4040" {
		t.Errorf("%d", v6)
	}

	v6, err = To6("64:ff9b::/64", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:ff9b::40:4040:4000:0" {
		t.Errorf("%d", v6)
	}

	v6, err = To6("64:ff9b::/56", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:ff9b:0:40:40:4040::" {
		t.Errorf("%d", v6)
	}

	v6, err = To6("64::/32", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:0:4040:4040::" {
		t.Errorf("%d", v6)
	}
}

func rr(rdef string) dns.RR {
	ret, err := dns.NewRR(rdef)
	if err != nil {
		panic(err)
	}
	return ret
}

func TestResponseShould(t *testing.T) {
	var tests = []struct {
		resp         dns.Msg
		translateAll bool
		expected     bool
	}{
		// If there's an AAAA record, then no
		{
			resp: dns.Msg{
				MsgHdr: dns.MsgHdr{
					Rcode: dns.RcodeSuccess,
				},
				Answer: []dns.RR{
					rr("example.com. IN AAAA ::1"),
				},
			},
			expected: false,
		},
		// If there's no AAAA, then true
		{
			resp: dns.Msg{
				MsgHdr: dns.MsgHdr{
					Rcode: dns.RcodeSuccess,
				},
				Ns: []dns.RR{
					rr("example.com. IN SOA foo bar 1 1 1 1 1"),
				},
			},
			expected: true,
		},
		// Failure, except NameError, should be true
		{
			resp: dns.Msg{
				MsgHdr: dns.MsgHdr{
					Rcode: dns.RcodeNotImplemented,
				},
				Ns: []dns.RR{
					rr("example.com. IN SOA foo bar 1 1 1 1 1"),
				},
			},
			expected: true,
		},
		// NameError should be false
		{
			resp: dns.Msg{
				MsgHdr: dns.MsgHdr{
					Rcode: dns.RcodeNameError,
				},
				Ns: []dns.RR{
					rr("example.com. IN SOA foo bar 1 1 1 1 1"),
				},
			},
			expected: false,
		},
		// If there's an AAAA record, but translateAll is configured, then yes
		{
			resp: dns.Msg{
				MsgHdr: dns.MsgHdr{
					Rcode: dns.RcodeSuccess,
				},
				Answer: []dns.RR{
					rr("example.com. IN AAAA ::1"),
				},
			},
			translateAll: true,
			expected:     true,
		},
	}

	d := DNS64{}

	for idx, tc := range tests {
		t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
			d.TranslateAll = tc.translateAll
			actual := d.responseShouldDNS64(&tc.resp)
			if actual != tc.expected {
				t.Fatalf("Expected responseShouldDNS64 %v got %v", tc.expected, actual)
			}
		})
	}
}

func TestDNS64(t *testing.T) {
	var cases = []struct {
		// a brief summary of the test case
		name string

		// the request
		req *dns.Msg

		// the initial response from the "downstream" server
		initResp *dns.Msg

		// A response to provide
		aResp *dns.Msg

		// the expected ultimate result
		resp *dns.Msg
	}{
		{
			// no AAAA record, yes A record. Do DNS64
			name: "standard flow",
			req: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					RecursionDesired: true,
					Opcode:           dns.OpcodeQuery,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
			},
			initResp: &dns.Msg{ //success, no answers
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Ns:       []dns.RR{rr("example.com. 70 IN SOA foo bar 1 1 1 1 1")},
			},
			aResp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               43,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeA, dns.ClassINET}},
				Answer: []dns.RR{
					rr("example.com. 60 IN A 192.0.2.42"),
					rr("example.com. 5000 IN A 192.0.2.43"),
				},
			},

			resp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Answer: []dns.RR{
					rr("example.com. 60 IN AAAA 64:ff9b::192.0.2.42"),
					// override RR ttl to SOA ttl, since it's lower
					rr("example.com. 70 IN AAAA 64:ff9b::192.0.2.43"),
				},
			},
		},
		{
			// name exists, but has neither A nor AAAA record
			name: "a empty",
			req: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					RecursionDesired: true,
					Opcode:           dns.OpcodeQuery,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
			},
			initResp: &dns.Msg{ //success, no answers
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Ns:       []dns.RR{rr("example.com. 3600 IN SOA foo bar 1 7200 900 1209600 86400")},
			},
			aResp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               43,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeA, dns.ClassINET}},
				Ns:       []dns.RR{rr("example.com. 3600 IN SOA foo bar 1 7200 900 1209600 86400")},
			},

			resp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Ns:       []dns.RR{rr("example.com. 3600 IN SOA foo bar 1 7200 900 1209600 86400")},
				Answer:   []dns.RR{}, // just to make comparison happy
			},
		},
		{
			// Query error other than NameError
			name: "non-nxdomain error",
			req: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					RecursionDesired: true,
					Opcode:           dns.OpcodeQuery,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
			},
			initResp: &dns.Msg{ // failure
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeRefused,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
			},
			aResp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               43,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeA, dns.ClassINET}},
				Answer: []dns.RR{
					rr("example.com. 60 IN A 192.0.2.42"),
					rr("example.com. 5000 IN A 192.0.2.43"),
				},
			},

			resp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Answer: []dns.RR{
					rr("example.com. 60 IN AAAA 64:ff9b::192.0.2.42"),
					rr("example.com. 600 IN AAAA 64:ff9b::192.0.2.43"),
				},
			},
		},
		{
			// nxdomain (NameError): don't even try an A request.
			name: "nxdomain",
			req: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					RecursionDesired: true,
					Opcode:           dns.OpcodeQuery,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
			},
			initResp: &dns.Msg{ // failure
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeNameError,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Ns:       []dns.RR{rr("example.com. 3600 IN SOA foo bar 1 7200 900 1209600 86400")},
			},
			resp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeNameError,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Ns:       []dns.RR{rr("example.com. 3600 IN SOA foo bar 1 7200 900 1209600 86400")},
			},
		},
		{
			// AAAA record exists
			name: "AAAA record",
			req: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					RecursionDesired: true,
					Opcode:           dns.OpcodeQuery,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
			},

			initResp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Answer: []dns.RR{
					rr("example.com. 60 IN AAAA ::1"),
					rr("example.com. 5000 IN AAAA ::2"),
				},
			},

			resp: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               42,
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
					Rcode:            dns.RcodeSuccess,
					Response:         true,
				},
				Question: []dns.Question{dns.Question{"example.com.", dns.TypeAAAA, dns.ClassINET}},
				Answer: []dns.RR{
					rr("example.com. 60 IN AAAA ::1"),
					rr("example.com. 5000 IN AAAA ::2"),
				},
			},
		},
	}

	_, pfx, _ := net.ParseCIDR("64:ff9b::/96")

	for idx, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", idx, tc.name), func(t *testing.T) {
			d := DNS64{
				Next:     &fakeHandler{t, tc.initResp},
				Prefix:   pfx,
				Upstream: &fakeUpstream{t, tc.req.Question[0].Name, tc.aResp},
			}

			rec := dnstest.NewRecorder(&test.ResponseWriter{RemoteIP: "::1"})
			rc, err := d.ServeDNS(context.Background(), rec, tc.req)
			if err != nil {
				t.Fatal(err)
			}
			actual := rec.Msg
			assert.Equal(t, actual.Rcode, rc, "ServeDNS should return real result code")

			assert.Equal(t, tc.resp, actual, "Final answer should match expected")
		})
	}
}

type fakeHandler struct {
	t     *testing.T
	reply *dns.Msg
}

func (fh *fakeHandler) ServeDNS(_ context.Context, w dns.ResponseWriter, _ *dns.Msg) (int, error) {
	if fh.reply == nil {
		panic("fakeHandler ServeDNS with nil reply")
	}
	w.WriteMsg(fh.reply)

	return fh.reply.Rcode, nil
}
func (fh *fakeHandler) Name() string {
	return "fake"
}

type fakeUpstream struct {
	t    *testing.T
	req  string
	resp *dns.Msg
}

func (fu *fakeUpstream) Lookup(_ context.Context, _ request.Request, name string, typ uint16) (*dns.Msg, error) {
	if fu.req == "" {
		fu.t.Fatalf("Unexpected A lookup for %s", name)
	}
	if name != fu.req {
		fu.t.Fatalf("Wrong A lookup for %s, expected %s", name, fu.req)
	}

	if typ != dns.TypeA {
		fu.t.Fatalf("Wrong lookup type %d, expected %d", typ, dns.TypeA)
	}

	return fu.resp, nil
}
