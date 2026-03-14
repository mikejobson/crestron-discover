package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// enableBroadcast sets SO_BROADCAST on the socket. This is required on macOS
// (and good practice on Linux) to send UDP packets to broadcast addresses.
func enableBroadcast(_ string, _ string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}

func main() {
	const (
		port        = 41794
		packetSize  = 316 // 0x13C
		broadcastIP = "255.255.255.255"
	)

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error getting hostname:", err)
		return
	}

	// Build the discovery packet
	packet := make([]byte, packetSize)
	// Fill with zeros by default

	// Ethernet header (not sent by UDP, but included for reference)
	// ff ff ff ff ff ff 2a 56 58 72 82 f6 08 00

	// IP/UDP header (not sent by UDP, but included for reference)
	// 45 00 01 26 a6 aa 00 00 40 11 c1 bf ac 10 65 4d ff ff ff ff e3 c3 a3 42 01 12 51 3f

	// Discovery payload (updated header)
	copy(packet[0:], []byte{
		0x14, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x03, 0x00, 0x00,
	})
	// Insert hostname at offset 0x1B (27)
	hostnameOffset := 27
	hostnameBytes := []byte(hostname)
	maxHostLen := 16
	if len(hostnameBytes) > maxHostLen {
		hostnameBytes = hostnameBytes[:maxHostLen]
	}
	copy(packet[hostnameOffset:], hostnameBytes)
	// The rest is already zero-padded

	// Bind a single UDP socket with SO_BROADCAST before sending so that:
	//   1. We don't miss replies that arrive before a separate listener is ready.
	//   2. The source port is 41794, so Crestron devices reply to the correct port.
	//   3. SO_BROADCAST is set — required on macOS to send to 255.255.255.255.
	lc := net.ListenConfig{
		Control: enableBroadcast,
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Printf("Error binding to port %d: %v\n", port, err)
		return
	}
	defer pc.Close()

	listener := pc.(*net.UDPConn)

	// Send the discovery broadcast from the already-bound socket.
	broadcastAddr := &net.UDPAddr{
		IP:   net.ParseIP(broadcastIP),
		Port: port,
	}
	fmt.Printf("Sending Crestron discovery packet as hostname '%s'...\n", hostname)
	_, err = listener.WriteTo(packet, broadcastAddr)
	if err != nil {
		fmt.Println("Error sending packet:", err)
		return
	}

	// Listen for replies on the same socket
	listener.SetReadBuffer(2048)
	listener.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Println("Waiting for replies (5s timeout)...")
	buf := make([]byte, 2048)
	localIPs := getLocalIPs()
	var responses []CrestronDevice
	for {
		n, src, err := listener.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if isLocalIP(src.IP, localIPs) {
			continue // Ignore our own device
		}
		device := parseCrestronResponse(buf[:n], src)
		if device != nil {
			responses = append(responses, *device)
		}
	}

	if len(responses) == 0 {
		fmt.Println("No devices found.")
		return
	}

	fmt.Printf("%-20s %-18s %-20s %-16s %-12s %-14s\n", "IP Address", "Model", "Serial", "Version", "Date", "MAC")
	fmt.Println(strings.Repeat("-", 104))
	for _, d := range responses {
		fmt.Printf("%-20s %-18s %-20s %-16s %-12s %-14s\n", d.IP, d.Model, d.Serial, d.Version, d.Date, d.MAC)
	}
	fmt.Println("Done.")

}

// CrestronDevice holds parsed device info
type CrestronDevice struct {
	IP      string
	Model   string
	Serial  string
	Version string
	Date    string
	MAC     string
}

// parseCrestronResponse parses a Crestron device response and returns a struct
func parseCrestronResponse(data []byte, src *net.UDPAddr) *CrestronDevice {
	if len(data) < 0x110 {
		return nil
	}
	model := string(bytes.Trim(data[0x0A:0x1A], "\x00"))
	// The version string is at 0x100, up to 64 bytes, null-terminated
	versionBlock := string(bytes.Trim(data[0x100:0x140], "\x00"))

	// Try to parse: model [version (date), #serial] @E-mac
	var version, date, serial, mac string
	var versionInfo string
	if i := strings.Index(versionBlock, "["); i != -1 {
		versionInfo = versionBlock[i+1:]
		if j := strings.Index(versionInfo, "]"); j != -1 {
			versionInfo = versionInfo[:j]
		}
		// versionInfo: v4.0004.00114 (Oct 18 2024), #FFFFFFFF
		parts := strings.Split(versionInfo, ",")
		if len(parts) > 0 {
			// version and date
			vparts := strings.SplitN(parts[0], "(", 2)
			version = strings.TrimSpace(vparts[0])
			if len(vparts) > 1 {
				date = strings.TrimSuffix(strings.TrimSpace(vparts[1]), ")")
			}
		}
		for _, p := range parts[1:] {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "#") {
				serial = strings.TrimPrefix(p, "#")
			}
		}
	}
	// MAC: search the entire response for '@E-' followed by 12 hex digits
	mac = ""
	macPattern := regexp.MustCompile(`@E-([0-9A-Fa-f]{12})`)
	macMatch := macPattern.FindSubmatch(data)
	if len(macMatch) == 2 {
		mac = string(macMatch[1])
	}
	return &CrestronDevice{
		IP:      src.IP.String(),
		Model:   model,
		Serial:  serial,
		Version: version,
		Date:    date,
		MAC:     mac,
	}
}

// getLocalIPs returns a map of all local IP addresses
func getLocalIPs() map[string]struct{} {
	ips := make(map[string]struct{})
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				ips[ip.String()] = struct{}{}
			}
		}
	}
	return ips
}

// isLocalIP checks if the given IP is one of the local machine's IPs
func isLocalIP(ip net.IP, localIPs map[string]struct{}) bool {
	_, exists := localIPs[ip.String()]
	return exists
}
