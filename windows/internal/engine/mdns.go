package engine

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lintianxu/lan-clip/windows/internal/proto"
	"golang.org/x/net/dns/dnsmessage"
)

type DiscoveredPeer struct {
	DeviceID    string
	DisplayName string
	IsPairing   bool
	Host        string
	Port        uint16
	LastSeen    time.Time
}

type mdnsService struct {
	mu           sync.Mutex
	selfID       string
	displayName  string
	hostLabel    string
	port         uint16
	isPairing    bool
	advertising  bool
	browsing     bool
	conn         *net.UDPConn
	stopCh       chan struct{}
	peers        map[string]DiscoveredPeer
	onPeers      func([]DiscoveredPeer)
}

func newMDNSService(selfID, displayName string) *mdnsService {
	short := selfID
	if len(short) > 8 {
		short = short[:8]
	}
	return &mdnsService{
		selfID:      selfID,
		displayName: displayName,
		hostLabel:   "lanclip-" + short + ".local.",
		peers:       make(map[string]DiscoveredPeer),
	}
}

func (m *mdnsService) ensureStartedLocked() error {
	if m.conn != nil {
		return nil
	}
	addr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		// Fallback to ephemeral UDP port for sending queries if 5353 is blocked
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return err
		}
	}
	m.conn = conn
	m.stopCh = make(chan struct{})
	go m.readLoop(conn, m.stopCh)
	go m.announceLoop(conn, m.stopCh)
	return nil
}

func (m *mdnsService) UpdateAdvertise(active bool, port uint16, pairing bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.advertising = active && port > 0
	m.port = port
	m.isPairing = pairing
	if m.advertising || m.browsing {
		if err := m.ensureStartedLocked(); err == nil && m.advertising {
			go m.sendAnnounce(m.conn)
		}
	} else {
		m.stopLocked()
	}
}

func (m *mdnsService) SetBrowsing(active bool, cb func([]DiscoveredPeer)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.browsing = active
	if cb != nil {
		m.onPeers = cb
	}
	if active {
		m.peers = make(map[string]DiscoveredPeer)
		if err := m.ensureStartedLocked(); err == nil {
			go m.sendQuery(m.conn)
		}
	} else if !m.advertising {
		m.stopLocked()
	}
}

func (m *mdnsService) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.advertising = false
	m.browsing = false
	m.stopLocked()
}

func (m *mdnsService) stopLocked() {
	if m.stopCh != nil {
		close(m.stopCh)
		m.stopCh = nil
	}
	if m.conn != nil {
		_ = m.conn.Close()
		m.conn = nil
	}
}

func (m *mdnsService) Snapshot() []DiscoveredPeer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sortedPeersLocked()
}

func (m *mdnsService) sortedPeersLocked() []DiscoveredPeer {
	cutoff := time.Now().Add(-20 * time.Second)
	out := make([]DiscoveredPeer, 0, len(m.peers))
	for k, p := range m.peers {
		if p.LastSeen.Before(cutoff) {
			delete(m.peers, k)
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsPairing != out[j].IsPairing {
			return out[i].IsPairing && !out[j].IsPairing
		}
		return out[i].DisplayName < out[j].DisplayName
	})
	return out
}

func (m *mdnsService) announceLoop(conn *net.UDPConn, stopCh chan struct{}) {
	ticker := time.NewTicker(1800 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			adv := m.advertising
			brow := m.browsing
			m.mu.Unlock()
			if adv {
				m.sendAnnounce(conn)
			}
			if brow {
				m.sendQuery(conn)
			}
		}
	}
}

func (m *mdnsService) sendQuery(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	qName, err := dnsmessage.NewName(proto.ServiceType + ".local.")
	if err != nil {
		return
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{
			{
				Name:  qName,
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	pkt, err := msg.Pack()
	if err != nil {
		return
	}
	_, _ = conn.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
}

func (m *mdnsService) sendAnnounce(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	m.mu.Lock()
	adv := m.advertising
	port := m.port
	pairing := m.isPairing
	name := m.displayName
	id := m.selfID
	hostLabel := m.hostLabel
	m.mu.Unlock()
	if !adv || port == 0 {
		return
	}
	ipStr := proto.DetectLocalLANIP()
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return
	}

	safeInst := strings.Map(func(r rune) rune {
		if r == '.' || r < 0x20 {
			return '-'
		}
		return r
	}, name)
	if safeInst == "" {
		safeInst = "LanClip"
	}
	srvTypeName, err1 := dnsmessage.NewName(proto.ServiceType + ".local.")
	instName, err2 := dnsmessage.NewName(safeInst + "-" + id[:4] + "." + proto.ServiceType + ".local.")
	hostName, err3 := dnsmessage.NewName(hostLabel)
	if err1 != nil || err2 != nil || err3 != nil {
		return
	}

	pairFlag := "0"
	if pairing {
		pairFlag = "1"
	}
	var ip4 [4]byte
	copy(ip4[:], ip[:4])

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: srvTypeName, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.PTRResource{PTR: instName},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: instName, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.SRVResource{Port: port, Target: hostName},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: instName, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120},
				Body: &dnsmessage.TXTResource{TXT: []string{
					"id=" + id,
					"name=" + name,
					"pairing=" + pairFlag,
					"port=" + strconv.Itoa(int(port)),
				}},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: hostName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.AResource{A: ip4},
			},
		},
	}
	pkt, err := msg.Pack()
	if err != nil {
		return
	}
	_, _ = conn.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
}

func (m *mdnsService) readLoop(conn *net.UDPConn, stopCh chan struct{}) {
	buf := make([]byte, 8192)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if src != nil && !proto.IsAllowedIP(src.IP) {
			continue
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !msg.Header.Response {
			for _, q := range msg.Questions {
				if strings.EqualFold(q.Name.String(), proto.ServiceType+".local.") {
					m.sendAnnounce(conn)
					break
				}
			}
			continue
		}
		m.parseResponse(&msg, src)
	}
}

func (m *mdnsService) parseResponse(msg *dnsmessage.Message, src *net.UDPAddr) {
	all := make([]dnsmessage.Resource, 0, len(msg.Answers)+len(msg.Additionals))
	all = append(all, msg.Answers...)
	all = append(all, msg.Additionals...)

	type srvInfo struct {
		target string
		port   uint16
	}
	srvByInst := map[string]srvInfo{}
	txtByInst := map[string]map[string]string{}
	aByHost := map[string]string{}

	for _, r := range all {
		name := strings.ToLower(r.Header.Name.String())
		switch body := r.Body.(type) {
		case *dnsmessage.SRVResource:
			srvByInst[name] = srvInfo{target: strings.ToLower(body.Target.String()), port: body.Port}
		case *dnsmessage.TXTResource:
			kv := map[string]string{}
			for _, item := range body.TXT {
				if idx := strings.IndexByte(item, '='); idx > 0 {
					kv[item[:idx]] = item[idx+1:]
				}
			}
			txtByInst[name] = kv
		case *dnsmessage.AResource:
			ip := net.IPv4(body.A[0], body.A[1], body.A[2], body.A[3])
			if proto.IsAllowedIP(ip) {
				aByHost[name] = ip.String()
			}
		}
	}

	var changed bool
	var cb func([]DiscoveredPeer)
	var snapshot []DiscoveredPeer

	m.mu.Lock()
	for inst, kv := range txtByInst {
		peerID := kv["id"]
		if peerID == "" || peerID == m.selfID {
			continue
		}
		peerName := kv["name"]
		if peerName == "" {
			peerName = fmt.Sprintf("Device-%s", peerID[:4])
		}
		isPairing := kv["pairing"] == "1"
		var port uint16 = proto.DefaultPort
		if p, err := strconv.Atoi(kv["port"]); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
		}
		hostIP := ""
		if srv, ok := srvByInst[inst]; ok {
			if srv.port > 0 {
				port = srv.port
			}
			hostIP = aByHost[srv.target]
		}
		if hostIP == "" && src != nil && src.IP.To4() != nil {
			hostIP = src.IP.To4().String()
		}
		if hostIP == "" {
			continue
		}
		m.peers[peerID] = DiscoveredPeer{
			DeviceID:    peerID,
			DisplayName: peerName,
			IsPairing:   isPairing,
			Host:        hostIP,
			Port:        port,
			LastSeen:    time.Now(),
		}
		changed = true
	}
	if changed && m.browsing && m.onPeers != nil {
		cb = m.onPeers
		snapshot = m.sortedPeersLocked()
	}
	m.mu.Unlock()

	if cb != nil {
		cb(snapshot)
	}
}
