package kubernetes

import (
	"fmt"
	"math"
	"net"
	"time"

	"github.com/miekg/coredns/middleware"
	"github.com/miekg/coredns/middleware/etcd/msg"
	"github.com/miekg/coredns/middleware/pkg/dnsutil"
	"github.com/miekg/coredns/request"

	"github.com/miekg/dns"
)

func (k Kubernetes) records(state request.Request, exact bool) ([]msg.Service, error) {
	services, err := k.Records(state.Name(), exact)
	if err != nil {
		return nil, err
	}
	// TODO: Do we want to support the SkyDNS (hacky) Group feature?
	services = msg.Group(services)
	return services, nil
}

// AAAA returns AAAA records from kubernetes or an error.
func (k Kubernetes) AAAA(zone string, state request.Request, previousRecords []dns.RR) (records []dns.RR, err error) {
	services, err := k.records(state, false)
	if err != nil {
		return nil, err
	}

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			// Try to resolve as CNAME if it's not an IP, but only if we don't create loops.
			if middleware.Name(state.Name()).Matches(dns.Fqdn(serv.Host)) {
				// x CNAME x is a direct loop, don't add those
				continue
			}

			newRecord := serv.NewCNAME(state.QName(), serv.Host)
			if len(previousRecords) > 7 {
				// don't add it, and just continue
				continue
			}
			if dnsutil.DuplicateCNAME(newRecord, previousRecords) {
				continue
			}

			state1 := state.NewWithQuestion(serv.Host, state.QType())
			nextRecords, err := k.AAAA(zone, state1, append(previousRecords, newRecord))

			if err == nil {
				// Not only have we found something we should add the CNAME and the IP addresses.
				if len(nextRecords) > 0 {
					records = append(records, newRecord)
					records = append(records, nextRecords...)
				}
				continue
			}
			// This means we can not complete the CNAME, try to look else where.
			target := newRecord.Target
			if dns.IsSubDomain(zone, target) {
				// We should already have found it
				continue
			}
			m1, e1 := k.Proxy.Lookup(state, target, state.QType())
			if e1 != nil {
				continue
			}
			// Len(m1.Answer) > 0 here is well?
			records = append(records, newRecord)
			records = append(records, m1.Answer...)
			continue
			// both here again
		case ip.To4() != nil:
			// nada?
		case ip.To4() == nil:
			records = append(records, serv.NewAAAA(state.QName(), ip.To16()))
		}
	}
	return records, nil
}

// SRV returns SRV records from kubernetes.
// If the Target is not a name but an IP address, a name is created on the fly and the IP address is put in
// the additional section.
func (k Kubernetes) SRV(zone string, state request.Request) (records []dns.RR, extra []dns.RR, err error) {
	services, err := k.records(state, false)
	if err != nil {
		return nil, nil, err
	}

	// Looping twice to get the right weight vs priority
	w := make(map[int]int)
	for _, serv := range services {
		weight := 100
		if serv.Weight != 0 {
			weight = serv.Weight
		}
		if _, ok := w[serv.Priority]; !ok {
			w[serv.Priority] = weight
			continue
		}
		w[serv.Priority] += weight
	}
	lookup := make(map[string]bool)
	for _, serv := range services {
		w1 := 100.0 / float64(w[serv.Priority])
		if serv.Weight == 0 {
			w1 *= 100
		} else {
			w1 *= float64(serv.Weight)
		}
		weight := uint16(math.Floor(w1))
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			srv := serv.NewSRV(state.QName(), weight)
			records = append(records, srv)

			if _, ok := lookup[srv.Target]; ok {
				break
			}

			lookup[srv.Target] = true

			if !dns.IsSubDomain(zone, srv.Target) {
				m1, e1 := k.Proxy.Lookup(state, srv.Target, dns.TypeA)
				if e1 == nil {
					extra = append(extra, m1.Answer...)
				}
				m1, e1 = k.Proxy.Lookup(state, srv.Target, dns.TypeAAAA)
				if e1 == nil {
					// If we have seen CNAME's we *assume* that they are already added.
					for _, a := range m1.Answer {
						if _, ok := a.(*dns.CNAME); !ok {
							extra = append(extra, a)
						}
					}
				}
				break
			}
			// Internal name, we should have some info on them, either v4 or v6
			// Clients expect a complete answer, because we are a recursor in their view.
			state1 := state.NewWithQuestion(srv.Target, dns.TypeA)
			addr, _, e1 := middleware.A(&k, zone, state1, nil, middleware.Options{})
			if e1 == nil {
				extra = append(extra, addr...)
			}
			// k.AAA(zone, state1, nil) as well...?
		case ip.To4() != nil:
			serv.Host = serv.Key
			srv := serv.NewSRV(state.QName(), weight)

			records = append(records, srv)
			extra = append(extra, serv.NewA(srv.Target, ip.To4()))
		case ip.To4() == nil:
			serv.Host = serv.Key
			srv := serv.NewSRV(state.QName(), weight)

			records = append(records, srv)
			extra = append(extra, serv.NewAAAA(srv.Target, ip.To16()))
		}
	}
	return records, extra, nil
}

// MX returns MX records from kubernetes. Not implemented!
func (k Kubernetes) MX(zone string, state request.Request) (records []dns.RR, extra []dns.RR, err error) {
	return nil, nil, err
}

// CNAME returns CNAME records from kubernetes. Not implemented!
func (k Kubernetes) CNAME(zone string, state request.Request) (records []dns.RR, err error) {
	return nil, err
}

// TXT returns TXT records from kubernetes. Not implemented!
func (k Kubernetes) TXT(zone string, state request.Request) (records []dns.RR, err error) {
	return nil, err
}

// NS returns NS records from kubernetes.
func (k Kubernetes) NS(zone string, state request.Request) (records, extra []dns.RR, err error) {
	// NS record for this zone live in a special place, ns.dns.<zone>. Fake our lookup.
	// only a tad bit fishy...
	old := state.QName()

	state.Clear()
	state.Req.Question[0].Name = "ns.dns." + zone
	services, err := k.records(state, false)
	if err != nil {
		return nil, nil, err
	}
	// ... and reset
	state.Req.Question[0].Name = old

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			return nil, nil, fmt.Errorf("NS record must be an IP address: %s", serv.Host)
		case ip.To4() != nil:
			serv.Host = serv.Key
			records = append(records, serv.NewNS(state.QName()))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			serv.Host = serv.Key
			records = append(records, serv.NewNS(state.QName()))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}

// SOA Record returns a SOA record from kubernetes.
func (k Kubernetes) SOA(zone string, state request.Request) *dns.SOA {
	header := dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Ttl: 300, Class: dns.ClassINET}
	return &dns.SOA{Hdr: header,
		Mbox:    "hostmaster." + zone,
		Ns:      "ns.dns." + zone,
		Serial:  uint32(time.Now().Unix()),
		Refresh: 7200,
		Retry:   1800,
		Expire:  86400,
		Minttl:  60,
	}
}

// PTR Record returns PTR records from kubernetes.
func (k Kubernetes) PTR(zone string, state request.Request) ([]dns.RR, error) {
	reverseIP := dnsutil.ExtractAddressFromReverse(state.Name())
	if reverseIP == "" {
		return nil, fmt.Errorf("does not support reverse lookup for %s", state.QName())
	}

	records := make([]dns.RR, 1)
	services, err := k.records(state, false)
	if err != nil {
		return nil, err
	}

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		if reverseIP != serv.Host {
			continue
		}
		switch {
		case ip.To4() != nil:
			records = append(records, serv.NewPTR(state.QName(), ip.To4().String()))
			break
		case ip.To4() == nil:
			// nodata?
		}
	}
	return records, nil
}
