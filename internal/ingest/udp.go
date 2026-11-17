package ingest

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/netsampler/goflow2/v2/utils"

	"github.com/trip-nine/flowtrim/internal/telemetry"
)

// udpServer owns sockets and decode workers. It replaces goflow2's receiver
// so we control SO_RCVBUF (the #1 cause of silent flow loss) and can count
// every drop.
type udpServer struct {
	conns   []*net.UDPConn
	work    chan *utils.Message
	wg      sync.WaitGroup
	recvWG  sync.WaitGroup
	log     *slog.Logger
	input   string
	stopped chan struct{}
}

var pktPool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}

func listenUDP(input, addr string, sockets, workers, queue, rcvbuf int, decode func(*utils.Message) error, log *slog.Logger) (*udpServer, error) {
	s := &udpServer{work: make(chan *utils.Message, queue), log: log, input: input, stopped: make(chan struct{})}
	lc := net.ListenConfig{Control: reusePortControl}
	for i := 0; i < sockets; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			s.close()
			return nil, err
		}
		c := pc.(*net.UDPConn)
		if rcvbuf > 0 {
			got := setRecvBuffer(c, rcvbuf)
			if i == 0 {
				if got < rcvbuf {
					log.Warn("UDP receive buffer smaller than requested; raise net.core.rmem_max (sysctl) or grant CAP_NET_ADMIN, or expect drops under bursts",
						"addr", addr, "requested", rcvbuf, "effective", got)
				} else {
					log.Info("UDP receive buffer", "addr", addr, "bytes", got)
				}
			}
		}
		s.conns = append(s.conns, c)
	}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for m := range s.work {
				if err := decode(m); err != nil {
					s.decodeErr(err)
				}
				b := m.Payload[:cap(m.Payload)]
				pktPool.Put(&b)
			}
		}()
	}
	for _, c := range s.conns {
		s.recvWG.Add(1)
		go s.recvLoop(c)
	}
	return s, nil
}

func (s *udpServer) recvLoop(c *net.UDPConn) {
	defer s.recvWG.Done()
	local := c.LocalAddr().(*net.UDPAddr).AddrPort()
	full := telemetry.FlowsRejected.WithLabelValues(s.input, "decode_queue_full_packets")
	for {
		bp := pktPool.Get().(*[]byte)
		buf := *bp
		n, src, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			pktPool.Put(bp)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-s.stopped:
				return
			default:
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		m := &utils.Message{Src: netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), Dst: local, Payload: buf[:n], Received: time.Now().UTC()}
		select {
		case s.work <- m:
		default:
			full.Inc() // decoders saturated: count, don't block the socket
			pktPool.Put(bp)
		}
	}
}

func (s *udpServer) decodeErr(err error) {
	var pe *utils.PipeMessageError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	reason := "decode_error"
	if isTemplateNotFound(err) {
		reason = "template_not_found_packets"
	}
	telemetry.FlowsRejected.WithLabelValues(s.input, reason).Inc()
	s.log.Debug("decode", "err", err)
}

func (s *udpServer) close() {
	select {
	case <-s.stopped:
		return
	default:
		close(s.stopped)
	}
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.recvWG.Wait()
	if s.work != nil {
		close(s.work)
	}
	s.wg.Wait()
}
