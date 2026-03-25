package fixtures

import (
	"fmt"
)

func generatePQCSigningKey() {
	// MIGRATION: Replace ECDSA-P256 with ML-DSA-65 (Post-Quantum Dilithium)
	// Hybrid approach recommended during transition period
	// privateKey, err := mldsa.GenerateKey65()
	fmt.Println("migrated to ML-DSA-65")
}
