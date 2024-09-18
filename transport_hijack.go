package dns

import (
	"context"
	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/logger"
	"net/netip"
	"os"
)

var _ Transport = (*HijackTransport)(nil)

func init() {
	RegisterTransport([]string{"hijack"}, func(options TransportOptions) (Transport, error) {
		return NewHijackTransport(options)
	})
}

type HijackTransport struct {
	name          string
	ctx           context.Context
	cancel        context.CancelFunc
	logger        logger.ContextLogger
	Inet4Response netip.Addr
	Inet6Response netip.Addr
}

func NewHijackTransport(options TransportOptions) (*HijackTransport, error) {
	ctx, cancel := context.WithCancel(options.Context)
	return &HijackTransport{
		name:          options.Name,
		ctx:           ctx,
		cancel:        cancel,
		logger:        options.Logger,
		Inet4Response: options.Inet4Response,
		Inet6Response: options.Inet6Response,
	}, nil
}

func (h *HijackTransport) Name() string {
	return h.name
}

func (h *HijackTransport) Start() error {
	return nil
}

func (h *HijackTransport) Reset() {}

func (h *HijackTransport) Close() error {
	h.cancel()
	return nil
}

func (h *HijackTransport) Raw() bool {
	return true
}

func (h *HijackTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	select {
	case <-h.ctx.Done():
		return nil, h.ctx.Err()
	default:
	}
	if len(message.Question) != 1 {
		if h.logger != nil {
			h.logger.InfoContext(ctx, "bad question count", len(message.Question))
		}
		return nil, os.ErrInvalid
	}
	question := message.Question[0]

	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       message.Id,
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: message.Question,
	}
	switch question.Qtype {
	case dns.TypeA:
		if h.Inet4Response.IsValid() {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    DefaultTTL,
				},
				A: h.Inet4Response.AsSlice(),
			})
		}
	case dns.TypeAAAA:
		if h.Inet6Response.IsValid() {
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    DefaultTTL,
				},
				AAAA: h.Inet6Response.AsSlice(),
			})
		}
	}

	return &response, nil
}

func (h *HijackTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}
