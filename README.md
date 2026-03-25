# QuantumShield

**Quantum-safe cryptography scanner and migration platform.**

Find quantum-vulnerable cryptography in your codebase. Assess migration risk. Generate fixes. Monitor continuously.

## Quick Start

```bash
# Install
go install github.com/jinglebells2020/quantumshield/cmd/qs@latest

# Scan a project
qs scan ./your-project

# Interactive TUI
qs

# Generate CBOM
qs cbom ./your-project --format json

# Compliance report
qs compliance ./your-project --framework "CNSA 2.0"
```

## What It Detects

| Algorithm | Quantum Threat | Replacement |
|---|---|---|
| RSA (all sizes) | Shor's algorithm | ML-KEM-768 |
| ECDSA / ECDH | Shor's algorithm | ML-DSA-65 / ML-KEM-768 |
| Ed25519 / DH | Shor's algorithm | ML-DSA / ML-KEM |
| AES-128 | Grover (64-bit) | AES-256 |
| DES / 3DES / RC4 | Broken | AES-256-GCM |
| MD5 / SHA-1 | Collisions + Grover | SHA-256 |
| TLS 1.0-1.2 (RSA/ECDHE) | Shor on key exchange | TLS 1.3 + PQ hybrid |
| X.509 certs (RSA/ECDSA) | Shor on public key | PQ certificates |

## Analysis Engines

- **Go AST**: Deep analysis with `go/ast`, key size extraction, import alias resolution
- **Python AST**: Embedded script bridge, Fernet/Django detection, variable taint
- **Java AST**: 24 JCE/BouncyCastle rules, variable tracking, `.initialize(N)` key sizes
- **JavaScript/TypeScript**: Node.js crypto, Web Crypto API, NodeRSA, node-forge
- **Terraform/IaC**: AWS KMS, ALB, GCP SSL, Azure Key Vault, Kubernetes manifests
- **X.509 Certificates**: PEM/DER parsing, expiry tracking, quantum risk assessment
- **Dependencies**: go.mod, package.json, requirements.txt, pom.xml with 15-package vuln DB
- **Cross-file taint**: Call graph + taint propagation across function/file boundaries

## Advanced Analytics (12 modules, pure Go)

FFT spectral analysis, Markov chain prediction, HMM/Viterbi pattern detection, Monte Carlo simulation, Bayesian FP reduction, spectral graph partitioning, TDA persistent homology, optimal stopping theory, HNDL attack lifecycle modeling, information-theoretic crypto strength assessment.

## Benchmarks

| Benchmark | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| NIST Juliet CWE-327/328 | 100% | 94.4% | 97.1% | 0% |
| OWASP Benchmark v1.2 | 100% | 84.6% | 91.6% | 0% |

## CLI Commands

| Command | Description |
|---|---|
| `qs` | Interactive TUI |
| `qs scan <path>` | Scan codebase |
| `qs monitor <path>` | Continuous monitoring |
| `qs cbom <path>` | Generate CBOM (CycloneDX v1.6) |
| `qs compliance <path>` | Compliance report (CNSA 2.0, NSM-10, PCI DSS) |
| `qs diff <path>` | Incremental scan (new/fixed only) |
| `qs cloud aws/gcp/azure` | Audit cloud KMS keys |
| `qs serve` | API server |
| `qs install-hook` | Git pre-commit hook |
| `qs version` | Version info |

## License

Apache 2.0
