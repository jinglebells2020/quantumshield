package models

import "time"

// TLSHandshake represents a captured TLS handshake observation.
type TLSHandshake struct {
	Timestamp      time.Time `json:"timestamp"`
	ServerIP       string    `json:"server_ip"`
	ServerPort     int       `json:"server_port"`
	CipherSuite    string    `json:"cipher_suite"`
	TLSVersion     string    `json:"tls_version"`
	KeyExchange    string    `json:"key_exchange"`
	PacketSizes    []int     `json:"packet_sizes"`
	InterArrivalMs []float64 `json:"inter_arrival_ms"`
	HandshakeDurMs float64   `json:"handshake_duration_ms"`
}
