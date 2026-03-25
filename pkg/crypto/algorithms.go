package crypto

type AlgorithmInfo struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	KeySize        int    `json:"key_size"`
	ClassicalBits  int    `json:"classical_security_bits"`
	QuantumBits    int    `json:"quantum_security_bits"`
	QuantumSafe    bool   `json:"quantum_safe"`
	Deprecated     bool   `json:"deprecated"`
	NISTApproved   bool   `json:"nist_approved"`
	Replacement    string `json:"replacement"`
}

var MigrationMap = map[string]MigrationPath{
	"RSA-1024":    {From: "RSA-1024", To: "ML-KEM-512", Hybrid: "RSA-3072 + ML-KEM-512", Effort: "medium", Priority: "critical"},
	"RSA-2048":    {From: "RSA-2048", To: "ML-KEM-768", Hybrid: "RSA-3072 + ML-KEM-768", Effort: "medium", Priority: "critical"},
	"RSA-3072":    {From: "RSA-3072", To: "ML-KEM-768", Hybrid: "RSA-3072 + ML-KEM-768", Effort: "medium", Priority: "high"},
	"RSA-4096":    {From: "RSA-4096", To: "ML-KEM-1024", Hybrid: "RSA-4096 + ML-KEM-1024", Effort: "medium", Priority: "high"},
	"ECDSA-P256":  {From: "ECDSA-P256", To: "ML-DSA-44", Hybrid: "ECDSA-P256 + ML-DSA-44", Effort: "medium", Priority: "critical"},
	"ECDSA-P384":  {From: "ECDSA-P384", To: "ML-DSA-65", Hybrid: "ECDSA-P384 + ML-DSA-65", Effort: "medium", Priority: "critical"},
	"ECDSA-P521":  {From: "ECDSA-P521", To: "ML-DSA-87", Hybrid: "ECDSA-P521 + ML-DSA-87", Effort: "medium", Priority: "high"},
	"Ed25519":     {From: "Ed25519", To: "ML-DSA-44", Hybrid: "Ed25519 + ML-DSA-44", Effort: "low", Priority: "high"},
	"ECDH-P256":   {From: "ECDH-P256", To: "ML-KEM-768", Hybrid: "X25519 + ML-KEM-768", Effort: "medium", Priority: "critical"},
	"ECDH-X25519": {From: "ECDH-X25519", To: "ML-KEM-768", Hybrid: "X25519 + ML-KEM-768", Effort: "low", Priority: "high"},
	"DH-2048":     {From: "DH-2048", To: "ML-KEM-768", Hybrid: "", Effort: "high", Priority: "critical"},
	"DSA":         {From: "DSA", To: "ML-DSA-44", Hybrid: "", Effort: "low", Priority: "critical"},
	"AES-128":     {From: "AES-128", To: "AES-256", Hybrid: "", Effort: "low", Priority: "medium"},
	"3DES":        {From: "3DES", To: "AES-256", Hybrid: "", Effort: "low", Priority: "high"},
	"Blowfish":    {From: "Blowfish", To: "AES-256", Hybrid: "", Effort: "low", Priority: "high"},
	"RC4":         {From: "RC4", To: "AES-256-GCM", Hybrid: "", Effort: "low", Priority: "critical"},
	"MD5":         {From: "MD5", To: "SHA-256", Hybrid: "", Effort: "low", Priority: "high"},
	"SHA-1":       {From: "SHA-1", To: "SHA-256", Hybrid: "", Effort: "low", Priority: "high"},
}

type MigrationPath struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Hybrid   string `json:"hybrid,omitempty"`
	Effort   string `json:"effort"`
	Priority string `json:"priority"`
}

func GetMigration(algo string) (MigrationPath, bool) {
	m, ok := MigrationMap[algo]
	return m, ok
}

var VulnerableAlgorithms = map[string]AlgorithmInfo{
	"RSA-2048": {
		Name: "RSA-2048", Type: "asymmetric", KeySize: 2048,
		ClassicalBits: 112, QuantumBits: 0, QuantumSafe: false,
		Replacement: "ML-KEM-768",
	},
	"RSA-4096": {
		Name: "RSA-4096", Type: "asymmetric", KeySize: 4096,
		ClassicalBits: 140, QuantumBits: 0, QuantumSafe: false,
		Replacement: "ML-KEM-1024",
	},
	"ECDSA-P256": {
		Name: "ECDSA-P256", Type: "signature", KeySize: 256,
		ClassicalBits: 128, QuantumBits: 0, QuantumSafe: false,
		Replacement: "ML-DSA-44",
	},
	"ECDH-P256": {
		Name: "ECDH-P256", Type: "key_exchange", KeySize: 256,
		ClassicalBits: 128, QuantumBits: 0, QuantumSafe: false,
		Replacement: "ML-KEM-768",
	},
	"AES-128": {
		Name: "AES-128", Type: "symmetric", KeySize: 128,
		ClassicalBits: 128, QuantumBits: 64, QuantumSafe: false,
		Replacement: "AES-256",
	},
	"AES-256": {
		Name: "AES-256", Type: "symmetric", KeySize: 256,
		ClassicalBits: 256, QuantumBits: 128, QuantumSafe: true,
		Replacement: "",
	},
}
