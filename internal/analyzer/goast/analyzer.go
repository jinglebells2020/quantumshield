// Package goast provides deep Go AST-based analysis for detecting
// quantum-vulnerable cryptographic usage. It replaces regex-based scanning
// with real AST analysis using go/ast, go/parser, and go/token for precise
// locations, key sizes, and usage context.
package goast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"time"

	"quantumshield/pkg/crypto"
	"quantumshield/pkg/models"
)

// Analyzer performs deep AST analysis on Go source files to detect
// quantum-vulnerable cryptographic usage patterns.
type Analyzer struct {
	confidence float64
}

// New creates a new Go AST analyzer with default settings.
func New() *Analyzer {
	return &Analyzer{
		confidence: 0.95,
	}
}

// cryptoImport tracks a resolved crypto package import.
type cryptoImport struct {
	localName  string // the alias or package name used in code
	importPath string // the full import path, e.g. "crypto/rsa"
}

// analysisContext holds state accumulated while walking a single file's AST.
type analysisContext struct {
	fset    *token.FileSet
	src     string   // raw source text
	lines   []string // source split into lines
	imports map[string]cryptoImport // localName -> cryptoImport
	findings []models.Finding
	filePath string
	// varSizes tracks variable names to byte-slice sizes per function scope,
	// populated from assignments like `key := make([]byte, N)` so that
	// aes.NewCipher(key) can resolve the key length.
	// Key format: "funcName:varName" (or ":varName" for package-level).
	varSizes map[string]int
	// funcRanges maps function start/end positions for scope resolution.
	funcRanges []funcRange
}

// knownCryptoPackages maps import paths to the default package name.
var knownCryptoPackages = map[string]string{
	"crypto/rsa":       "rsa",
	"crypto/ecdsa":     "ecdsa",
	"crypto/ecdh":      "ecdh",
	"crypto/elliptic":  "elliptic",
	"crypto/aes":       "aes",
	"crypto/des":       "des",
	"crypto/rc4":       "rc4",
	"crypto/md5":       "md5",
	"crypto/sha1":      "sha1",
	"crypto/hmac":      "hmac",
	"crypto/tls":       "tls",
	"crypto/x509":      "x509",
	"crypto/sha256":    "sha256",
	"crypto/sha512":    "sha512",
}

// AnalyzeFile parses a Go source file and returns findings for any
// quantum-vulnerable cryptographic usage.
func (a *Analyzer) AnalyzeFile(filePath string, src []byte) ([]models.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, src, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filePath, err)
	}

	srcStr := string(src)
	lines := strings.Split(srcStr, "\n")

	ctx := &analysisContext{
		fset:     fset,
		src:      srcStr,
		lines:    lines,
		imports:  make(map[string]cryptoImport),
		varSizes: make(map[string]int),
		filePath: filePath,
	}

	// First pass: collect crypto imports and resolve aliases.
	a.collectImports(file, ctx)

	// Second pass: collect variable sizes from assignments like
	// `key := make([]byte, N)` so we can resolve them in crypto calls.
	a.collectVarSizes(file, ctx)

	// Third pass: walk the full AST looking for crypto call patterns.
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			a.analyzeCallExpr(node, ctx)
		case *ast.CompositeLit:
			a.analyzeCompositeLit(node, ctx)
		}
		return true
	})

	return ctx.findings, nil
}

// collectImports walks the file's import declarations and records any crypto
// packages, mapping their local alias to the full import path.
func (a *Analyzer) collectImports(file *ast.File, ctx *analysisContext) {
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		defaultName, isCrypto := knownCryptoPackages[path]
		if !isCrypto {
			continue
		}
		localName := defaultName
		if imp.Name != nil {
			localName = imp.Name.Name
		}
		ctx.imports[localName] = cryptoImport{
			localName:  localName,
			importPath: path,
		}
	}
}

// funcRange records a function's position span and name for scope resolution.
type funcRange struct {
	name  string
	start token.Pos
	end   token.Pos
}

// collectVarSizes walks the AST to find short variable declarations and
// assignment statements of the form `v := make([]byte, N)` or `v := []byte{...}`
// and records the byte-slice length scoped to the enclosing function so that
// identically-named variables in different functions do not collide.
func (a *Analyzer) collectVarSizes(file *ast.File, ctx *analysisContext) {
	// First, collect all function ranges.
	ast.Inspect(file, func(n ast.Node) bool {
		fn, isFn := n.(*ast.FuncDecl)
		if isFn && fn.Body != nil {
			ctx.funcRanges = append(ctx.funcRanges, funcRange{
				name:  fn.Name.Name,
				start: fn.Body.Pos(),
				end:   fn.Body.End(),
			})
		}
		return true
	})

	// Then, collect variable sizes with scope keys.
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
				ident, isIdent := node.Lhs[0].(*ast.Ident)
				if !isIdent {
					return true
				}
				size := a.extractByteSizeFromExpr(node.Rhs[0])
				if size > 0 {
					scope := a.enclosingFunc(node.Pos(), ctx)
					ctx.varSizes[scope+":"+ident.Name] = size
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == 1 && len(node.Values) == 1 {
				size := a.extractByteSizeFromExpr(node.Values[0])
				if size > 0 {
					scope := a.enclosingFunc(node.Pos(), ctx)
					ctx.varSizes[scope+":"+node.Names[0].Name] = size
				}
			}
		}
		return true
	})
}

// enclosingFunc returns the name of the function that contains the given position,
// or "" for package-level declarations.
func (a *Analyzer) enclosingFunc(pos token.Pos, ctx *analysisContext) string {
	for _, fr := range ctx.funcRanges {
		if pos >= fr.start && pos <= fr.end {
			return fr.name
		}
	}
	return ""
}

// extractByteSizeFromExpr extracts the byte-slice length from expressions like
// make([]byte, N) or []byte{...}.
func (a *Analyzer) extractByteSizeFromExpr(expr ast.Expr) int {
	// Check for make([]byte, N).
	call, isCall := expr.(*ast.CallExpr)
	if isCall {
		ident, isIdent := call.Fun.(*ast.Ident)
		if isIdent && ident.Name == "make" && len(call.Args) >= 2 {
			if lit, isLit := call.Args[1].(*ast.BasicLit); isLit && lit.Kind == token.INT {
				if val, err := strconv.Atoi(lit.Value); err == nil {
					return val
				}
			}
		}
	}

	// Check for []byte{...} composite literal.
	compLit, isComp := expr.(*ast.CompositeLit)
	if isComp {
		return len(compLit.Elts)
	}

	return 0
}

// resolveSelector checks if a selector expression (X.Sel) refers to a known
// crypto package. Returns the import path and true if resolved.
func (a *Analyzer) resolveSelector(sel *ast.SelectorExpr, ctx *analysisContext) (importPath string, ok bool) {
	ident, isIdent := sel.X.(*ast.Ident)
	if !isIdent {
		return "", false
	}
	ci, found := ctx.imports[ident.Name]
	if !found {
		return "", false
	}
	return ci.importPath, true
}

// position extracts the file position from a token.Pos.
func (a *Analyzer) position(pos token.Pos, ctx *analysisContext) token.Position {
	return ctx.fset.Position(pos)
}

// snippet extracts the source code line for a given line number (1-indexed).
func (a *Analyzer) snippet(lineNum int, ctx *analysisContext) string {
	if lineNum < 1 || lineNum > len(ctx.lines) {
		return ""
	}
	return strings.TrimSpace(ctx.lines[lineNum-1])
}

// addFinding creates a Finding and appends it to the context.
func (a *Analyzer) addFinding(ctx *analysisContext, pos token.Position, endPos token.Position, info findingInfo) {
	snippet := a.snippet(pos.Line, ctx)

	algo := info.algorithm
	replacement := ""
	effort := "medium"
	if mig, ok := crypto.GetMigration(algo); ok {
		replacement = mig.To
		effort = mig.Effort
	}

	f := models.Finding{
		ID:              fmt.Sprintf("goast-%s-%d-%s", sanitizeID(ctx.filePath), pos.Line, sanitizeID(algo)),
		RuleID:          fmt.Sprintf("goast-%s", strings.ToLower(sanitizeID(algo))),
		Severity:        info.severity,
		Category:        info.category,
		QuantumThreat:   info.threat,
		FilePath:        ctx.filePath,
		LineStart:       pos.Line,
		LineEnd:         endPos.Line,
		ColumnStart:     pos.Column,
		ColumnEnd:       endPos.Column,
		CodeSnippet:     snippet,
		Algorithm:       algo,
		KeySize:         info.keySize,
		Usage:           info.usage,
		Library:         info.library,
		Language:        "go",
		Description:     info.description,
		ReplacementAlgo: replacement,
		MigrationEffort: effort,
		AutoFixAvailable: false,
		Confidence:      a.confidence,
		CreatedAt:       time.Now(),
	}

	ctx.findings = append(ctx.findings, f)
}

type findingInfo struct {
	algorithm   string
	severity    models.Severity
	category    models.AlgorithmCategory
	threat      models.QuantumThreatLevel
	keySize     int
	usage       string
	library     string
	description string
}

// analyzeCallExpr inspects a function call expression for crypto usage.
func (a *Analyzer) analyzeCallExpr(call *ast.CallExpr, ctx *analysisContext) {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return
	}

	importPath, ok := a.resolveSelector(sel, ctx)
	if !ok {
		return
	}

	funcName := sel.Sel.Name
	pos := a.position(call.Pos(), ctx)
	endPos := a.position(call.End(), ctx)

	switch importPath {
	case "crypto/rsa":
		a.analyzeRSA(funcName, call, pos, endPos, ctx)
	case "crypto/ecdsa":
		a.analyzeECDSA(funcName, call, pos, endPos, ctx)
	case "crypto/ecdh":
		a.analyzeECDH(funcName, call, pos, endPos, ctx)
	case "crypto/elliptic":
		a.analyzeElliptic(funcName, call, pos, endPos, ctx)
	case "crypto/aes":
		a.analyzeAES(funcName, call, pos, endPos, ctx)
	case "crypto/des":
		a.analyzeDES(funcName, call, pos, endPos, ctx)
	case "crypto/rc4":
		a.analyzeRC4(funcName, call, pos, endPos, ctx)
	case "crypto/md5":
		a.analyzeMD5(funcName, call, pos, endPos, ctx)
	case "crypto/sha1":
		a.analyzeSHA1(funcName, call, pos, endPos, ctx)
	case "crypto/hmac":
		a.analyzeHMAC(funcName, call, pos, endPos, ctx)
	case "crypto/x509":
		a.analyzeX509(funcName, call, pos, endPos, ctx)
	}
}

// analyzeRSA handles all crypto/rsa function calls.
func (a *Analyzer) analyzeRSA(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	switch funcName {
	case "GenerateKey":
		keySize := a.extractKeySizeArg(call, 1) // second argument is key size
		algo := "RSA"
		if keySize > 0 {
			algo = fmt.Sprintf("RSA-%d", keySize)
		}
		severity := models.SeverityCritical
		if keySize >= 4096 {
			severity = models.SeverityHigh
		}
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   algo,
			severity:    severity,
			category:    models.CategoryAsymmetricEncryption,
			threat:      models.ThreatBrokenByShor,
			keySize:     keySize,
			usage:       "key-generation",
			library:     "crypto/rsa",
			description: fmt.Sprintf("RSA key generation with %d-bit key is vulnerable to Shor's algorithm on quantum computers", keySize),
		})
	case "EncryptOAEP":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "RSA-OAEP",
			severity:    models.SeverityCritical,
			category:    models.CategoryAsymmetricEncryption,
			threat:      models.ThreatBrokenByShor,
			usage:       "encryption",
			library:     "crypto/rsa",
			description: "RSA-OAEP encryption is vulnerable to Shor's algorithm on quantum computers",
		})
	case "DecryptOAEP":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "RSA-OAEP",
			severity:    models.SeverityCritical,
			category:    models.CategoryAsymmetricEncryption,
			threat:      models.ThreatBrokenByShor,
			usage:       "decryption",
			library:     "crypto/rsa",
			description: "RSA-OAEP decryption is vulnerable to Shor's algorithm on quantum computers",
		})
	case "EncryptPKCS1v15":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "RSA-PKCS1v15",
			severity:    models.SeverityCritical,
			category:    models.CategoryAsymmetricEncryption,
			threat:      models.ThreatBrokenByShor,
			usage:       "encryption",
			library:     "crypto/rsa",
			description: "RSA PKCS#1 v1.5 encryption is vulnerable to Shor's algorithm and padding oracle attacks",
		})
	case "DecryptPKCS1v15":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "RSA-PKCS1v15",
			severity:    models.SeverityCritical,
			category:    models.CategoryAsymmetricEncryption,
			threat:      models.ThreatBrokenByShor,
			usage:       "decryption",
			library:     "crypto/rsa",
			description: "RSA PKCS#1 v1.5 decryption is vulnerable to Shor's algorithm and padding oracle attacks",
		})
	case "SignPSS":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "RSA-PSS",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "signing",
			library:     "crypto/rsa",
			description: "RSA-PSS digital signature is vulnerable to Shor's algorithm on quantum computers",
		})
	case "SignPKCS1v15":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "RSA-PKCS1v15",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "signing",
			library:     "crypto/rsa",
			description: "RSA PKCS#1 v1.5 signature is vulnerable to Shor's algorithm on quantum computers",
		})
	}
}

// analyzeECDSA handles all crypto/ecdsa function calls.
func (a *Analyzer) analyzeECDSA(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	switch funcName {
	case "GenerateKey":
		curveName := a.extractCurveName(call, 0, ctx)
		algo := "ECDSA"
		if curveName != "" {
			algo = fmt.Sprintf("ECDSA-%s", curveName)
		}
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   algo,
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "key-generation",
			library:     "crypto/ecdsa",
			description: fmt.Sprintf("ECDSA key generation (%s) is vulnerable to Shor's algorithm on quantum computers", algo),
		})
	case "Sign":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDSA",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "signing",
			library:     "crypto/ecdsa",
			description: "ECDSA signing is vulnerable to Shor's algorithm on quantum computers",
		})
	case "SignASN1":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDSA",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "signing",
			library:     "crypto/ecdsa",
			description: "ECDSA ASN.1 signing is vulnerable to Shor's algorithm on quantum computers",
		})
	case "Verify":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDSA",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "verification",
			library:     "crypto/ecdsa",
			description: "ECDSA verification relies on elliptic curve cryptography vulnerable to Shor's algorithm",
		})
	case "VerifyASN1":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDSA",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "verification",
			library:     "crypto/ecdsa",
			description: "ECDSA ASN.1 verification relies on elliptic curve cryptography vulnerable to Shor's algorithm",
		})
	}
}

// analyzeECDH handles all crypto/ecdh function calls.
func (a *Analyzer) analyzeECDH(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	switch funcName {
	case "P256":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDH-P256",
			severity:    models.SeverityCritical,
			category:    models.CategoryKeyExchange,
			threat:      models.ThreatBrokenByShor,
			usage:       "key-exchange",
			library:     "crypto/ecdh",
			description: "ECDH P-256 key exchange is vulnerable to Shor's algorithm on quantum computers",
		})
	case "P384":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDH-P384",
			severity:    models.SeverityCritical,
			category:    models.CategoryKeyExchange,
			threat:      models.ThreatBrokenByShor,
			usage:       "key-exchange",
			library:     "crypto/ecdh",
			description: "ECDH P-384 key exchange is vulnerable to Shor's algorithm on quantum computers",
		})
	case "P521":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDH-P521",
			severity:    models.SeverityCritical,
			category:    models.CategoryKeyExchange,
			threat:      models.ThreatBrokenByShor,
			usage:       "key-exchange",
			library:     "crypto/ecdh",
			description: "ECDH P-521 key exchange is vulnerable to Shor's algorithm on quantum computers",
		})
	case "X25519":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDH-X25519",
			severity:    models.SeverityHigh,
			category:    models.CategoryKeyExchange,
			threat:      models.ThreatBrokenByShor,
			usage:       "key-exchange",
			library:     "crypto/ecdh",
			description: "ECDH X25519 key exchange is vulnerable to Shor's algorithm on quantum computers",
		})
	}
}

// analyzeElliptic handles all crypto/elliptic function calls.
func (a *Analyzer) analyzeElliptic(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	switch funcName {
	case "P256":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDSA-P256",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "curve-instantiation",
			library:     "crypto/elliptic",
			description: "Elliptic curve P-256 is vulnerable to Shor's algorithm on quantum computers",
		})
	case "P384":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDSA-P384",
			severity:    models.SeverityCritical,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "curve-instantiation",
			library:     "crypto/elliptic",
			description: "Elliptic curve P-384 is vulnerable to Shor's algorithm on quantum computers",
		})
	case "P521":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "ECDSA-P521",
			severity:    models.SeverityHigh,
			category:    models.CategoryDigitalSignature,
			threat:      models.ThreatBrokenByShor,
			usage:       "curve-instantiation",
			library:     "crypto/elliptic",
			description: "Elliptic curve P-521 is vulnerable to Shor's algorithm on quantum computers",
		})
	}
}

// analyzeAES handles crypto/aes function calls.
func (a *Analyzer) analyzeAES(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	if funcName != "NewCipher" {
		return
	}

	keySize := a.inferAESKeySize(call, ctx)
	algo := "AES"
	severity := models.SeverityMedium
	threat := models.ThreatWeakenedByGrover
	description := "AES usage detected; key size could not be determined from AST"

	switch keySize {
	case 16:
		algo = "AES-128"
		severity = models.SeverityMedium
		description = "AES-128 provides only 64-bit security against Grover's algorithm; migrate to AES-256"
	case 24:
		algo = "AES-192"
		severity = models.SeverityLow
		description = "AES-192 provides 96-bit security against Grover's algorithm; consider AES-256"
	case 32:
		algo = "AES-256"
		severity = models.SeverityLow
		threat = models.ThreatWeakenedByGrover
		description = "AES-256 provides 128-bit quantum security; considered quantum-resistant"
	}

	keySizeBits := keySize * 8
	if keySize == 0 {
		keySizeBits = 0
	}

	a.addFinding(ctx, pos, endPos, findingInfo{
		algorithm:   algo,
		severity:    severity,
		category:    models.CategorySymmetricEncryption,
		threat:      threat,
		keySize:     keySizeBits,
		usage:       "cipher-creation",
		library:     "crypto/aes",
		description: description,
	})
}

// analyzeDES handles crypto/des function calls.
func (a *Analyzer) analyzeDES(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	switch funcName {
	case "NewTripleDESCipher":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "3DES",
			severity:    models.SeverityHigh,
			category:    models.CategorySymmetricEncryption,
			threat:      models.ThreatWeakenedByGrover,
			keySize:     168,
			usage:       "cipher-creation",
			library:     "crypto/des",
			description: "Triple DES is deprecated and provides inadequate security; migrate to AES-256",
		})
	case "NewCipher":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "DES",
			severity:    models.SeverityCritical,
			category:    models.CategorySymmetricEncryption,
			threat:      models.ThreatWeakenedByGrover,
			keySize:     56,
			usage:       "cipher-creation",
			library:     "crypto/des",
			description: "DES is completely broken and must not be used; migrate to AES-256",
		})
	}
}

// analyzeRC4 handles crypto/rc4 function calls.
func (a *Analyzer) analyzeRC4(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	if funcName != "NewCipher" {
		return
	}
	a.addFinding(ctx, pos, endPos, findingInfo{
		algorithm:   "RC4",
		severity:    models.SeverityCritical,
		category:    models.CategorySymmetricEncryption,
		threat:      models.ThreatWeakenedByGrover,
		usage:       "cipher-creation",
		library:     "crypto/rc4",
		description: "RC4 is cryptographically broken and must not be used; migrate to AES-256-GCM",
	})
}

// analyzeMD5 handles crypto/md5 function calls.
func (a *Analyzer) analyzeMD5(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	switch funcName {
	case "New":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "MD5",
			severity:    models.SeverityHigh,
			category:    models.CategoryHashing,
			threat:      models.ThreatWeakenedByGrover,
			usage:       "hash-creation",
			library:     "crypto/md5",
			description: "MD5 is cryptographically broken; migrate to SHA-256 or SHA-3",
		})
	case "Sum":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "MD5",
			severity:    models.SeverityHigh,
			category:    models.CategoryHashing,
			threat:      models.ThreatWeakenedByGrover,
			usage:       "hashing",
			library:     "crypto/md5",
			description: "MD5 hashing is cryptographically broken; migrate to SHA-256 or SHA-3",
		})
	}
}

// analyzeSHA1 handles crypto/sha1 function calls.
func (a *Analyzer) analyzeSHA1(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	switch funcName {
	case "New":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "SHA-1",
			severity:    models.SeverityHigh,
			category:    models.CategoryHashing,
			threat:      models.ThreatWeakenedByGrover,
			usage:       "hash-creation",
			library:     "crypto/sha1",
			description: "SHA-1 is cryptographically weak; migrate to SHA-256 or SHA-3",
		})
	case "Sum":
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "SHA-1",
			severity:    models.SeverityHigh,
			category:    models.CategoryHashing,
			threat:      models.ThreatWeakenedByGrover,
			usage:       "hashing",
			library:     "crypto/sha1",
			description: "SHA-1 hashing is cryptographically weak; migrate to SHA-256 or SHA-3",
		})
	}
}

// analyzeHMAC handles crypto/hmac function calls.
func (a *Analyzer) analyzeHMAC(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	if funcName != "New" {
		return
	}

	// Check if the first argument is sha1.New (indicating a weak HMAC).
	if len(call.Args) > 0 {
		if a.isWeakHashConstructor(call.Args[0], ctx) {
			a.addFinding(ctx, pos, endPos, findingInfo{
				algorithm:   "HMAC-SHA1",
				severity:    models.SeverityHigh,
				category:    models.CategoryHashing,
				threat:      models.ThreatWeakenedByGrover,
				usage:       "mac-creation",
				library:     "crypto/hmac",
				description: "HMAC with SHA-1 is weak; use HMAC-SHA-256 or HMAC-SHA-3",
			})
			return
		}
		if a.isMD5Constructor(call.Args[0], ctx) {
			a.addFinding(ctx, pos, endPos, findingInfo{
				algorithm:   "HMAC-MD5",
				severity:    models.SeverityHigh,
				category:    models.CategoryHashing,
				threat:      models.ThreatWeakenedByGrover,
				usage:       "mac-creation",
				library:     "crypto/hmac",
				description: "HMAC with MD5 is weak; use HMAC-SHA-256 or HMAC-SHA-3",
			})
			return
		}
	}
}

// analyzeX509 handles crypto/x509 function calls.
func (a *Analyzer) analyzeX509(funcName string, call *ast.CallExpr, pos, endPos token.Position, ctx *analysisContext) {
	if funcName != "CreateCertificate" {
		return
	}
	a.addFinding(ctx, pos, endPos, findingInfo{
		algorithm:   "X.509",
		severity:    models.SeverityHigh,
		category:    models.CategoryCertificate,
		threat:      models.ThreatBrokenByShor,
		usage:       "certificate-creation",
		library:     "crypto/x509",
		description: "X.509 certificate creation likely uses RSA or ECDSA keys vulnerable to Shor's algorithm",
	})
}

// analyzeCompositeLit handles composite literals, specifically tls.Config{}.
func (a *Analyzer) analyzeCompositeLit(lit *ast.CompositeLit, ctx *analysisContext) {
	sel, isSel := lit.Type.(*ast.SelectorExpr)
	if !isSel {
		return
	}

	importPath, ok := a.resolveSelector(sel, ctx)
	if !ok || importPath != "crypto/tls" {
		return
	}

	if sel.Sel.Name != "Config" {
		return
	}

	pos := a.position(lit.Pos(), ctx)
	endPos := a.position(lit.End(), ctx)

	// Inspect fields for MinVersion and CipherSuites.
	hasMinVersion := false
	hasCipherSuites := false

	for _, elt := range lit.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			continue
		}
		keyIdent, isIdent := kv.Key.(*ast.Ident)
		if !isIdent {
			continue
		}

		switch keyIdent.Name {
		case "MinVersion":
			hasMinVersion = true
			a.analyzeTLSMinVersion(kv.Value, pos, endPos, ctx)
		case "CipherSuites":
			hasCipherSuites = true
			a.analyzeTLSCipherSuites(kv.Value, pos, endPos, ctx)
		}
	}

	// If tls.Config is present but neither field is explicitly configured,
	// that itself is a finding (defaults may be insecure).
	if !hasMinVersion && !hasCipherSuites {
		a.addFinding(ctx, pos, endPos, findingInfo{
			algorithm:   "TLS",
			severity:    models.SeverityHigh,
			category:    models.CategoryTLSCipherSuite,
			threat:      models.ThreatBrokenByShor,
			usage:       "tls-configuration",
			library:     "crypto/tls",
			description: "TLS configuration without explicit MinVersion or CipherSuites may use quantum-vulnerable defaults",
		})
	}
}

// analyzeTLSMinVersion checks the MinVersion value in a tls.Config.
func (a *Analyzer) analyzeTLSMinVersion(expr ast.Expr, pos, endPos token.Position, ctx *analysisContext) {
	// Check for tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13
	sel, isSel := expr.(*ast.SelectorExpr)
	if !isSel {
		return
	}

	severity := models.SeverityHigh
	desc := "TLS configuration uses quantum-vulnerable key exchange"

	switch sel.Sel.Name {
	case "VersionTLS10":
		severity = models.SeverityCritical
		desc = "TLS 1.0 is deprecated and uses quantum-vulnerable key exchange mechanisms"
	case "VersionTLS11":
		severity = models.SeverityCritical
		desc = "TLS 1.1 is deprecated and uses quantum-vulnerable key exchange mechanisms"
	case "VersionTLS12":
		severity = models.SeverityHigh
		desc = "TLS 1.2 key exchange (ECDHE/DHE) is vulnerable to Shor's algorithm; migrate to post-quantum TLS"
	case "VersionTLS13":
		severity = models.SeverityHigh
		desc = "TLS 1.3 key exchange (ECDHE/X25519) is vulnerable to Shor's algorithm; migrate to post-quantum TLS"
	default:
		return
	}

	a.addFinding(ctx, pos, endPos, findingInfo{
		algorithm:   "TLS",
		severity:    severity,
		category:    models.CategoryTLSCipherSuite,
		threat:      models.ThreatBrokenByShor,
		usage:       "tls-configuration",
		library:     "crypto/tls",
		description: desc,
	})
}

// analyzeTLSCipherSuites checks the CipherSuites array in a tls.Config.
func (a *Analyzer) analyzeTLSCipherSuites(expr ast.Expr, pos, endPos token.Position, ctx *analysisContext) {
	comp, isComp := expr.(*ast.CompositeLit)
	if !isComp {
		return
	}

	for _, elt := range comp.Elts {
		sel, isSel := elt.(*ast.SelectorExpr)
		if !isSel {
			continue
		}
		suiteName := sel.Sel.Name
		// Any TLS cipher suite using RSA or ECDHE key exchange is quantum-vulnerable.
		if strings.Contains(suiteName, "RSA") || strings.Contains(suiteName, "ECDHE") {
			eltPos := a.position(sel.Pos(), ctx)
			eltEndPos := a.position(sel.End(), ctx)
			a.addFinding(ctx, eltPos, eltEndPos, findingInfo{
				algorithm:   suiteName,
				severity:    models.SeverityHigh,
				category:    models.CategoryTLSCipherSuite,
				threat:      models.ThreatBrokenByShor,
				usage:       "cipher-suite",
				library:     "crypto/tls",
				description: fmt.Sprintf("TLS cipher suite %s uses quantum-vulnerable key exchange", suiteName),
			})
		}
	}
}

// extractKeySizeArg extracts an integer literal from a call argument at the given index.
func (a *Analyzer) extractKeySizeArg(call *ast.CallExpr, argIndex int) int {
	if argIndex >= len(call.Args) {
		return 0
	}

	arg := call.Args[argIndex]

	// Direct integer literal: rsa.GenerateKey(rand.Reader, 2048)
	if lit, isLit := arg.(*ast.BasicLit); isLit && lit.Kind == token.INT {
		if val, err := strconv.Atoi(lit.Value); err == nil {
			return val
		}
	}

	return 0
}

// extractCurveName tries to determine the elliptic curve name from a call argument.
// For example, in ecdsa.GenerateKey(elliptic.P256(), rand.Reader), it extracts "P256".
func (a *Analyzer) extractCurveName(call *ast.CallExpr, argIndex int, ctx *analysisContext) string {
	if argIndex >= len(call.Args) {
		return ""
	}

	arg := call.Args[argIndex]

	// Check for elliptic.P256() style calls.
	callArg, isCall := arg.(*ast.CallExpr)
	if !isCall {
		return ""
	}

	sel, isSel := callArg.Fun.(*ast.SelectorExpr)
	if !isSel {
		return ""
	}

	importPath, ok := a.resolveSelector(sel, ctx)
	if !ok {
		return ""
	}

	if importPath == "crypto/elliptic" || importPath == "crypto/ecdh" {
		return sel.Sel.Name
	}

	return ""
}

// inferAESKeySize tries to determine the AES key size from the argument to aes.NewCipher.
// It handles make([]byte, N) and variable references to byte slices.
func (a *Analyzer) inferAESKeySize(call *ast.CallExpr, ctx *analysisContext) int {
	if len(call.Args) == 0 {
		return 0
	}

	arg := call.Args[0]

	// Check for make([]byte, N) pattern passed directly.
	makeCall, isCall := arg.(*ast.CallExpr)
	if isCall {
		ident, isIdent := makeCall.Fun.(*ast.Ident)
		if isIdent && ident.Name == "make" && len(makeCall.Args) >= 2 {
			if lit, isLit := makeCall.Args[1].(*ast.BasicLit); isLit && lit.Kind == token.INT {
				if val, err := strconv.Atoi(lit.Value); err == nil {
					return val
				}
			}
		}
	}

	// Check for a direct []byte{...} composite literal.
	compLit, isComp := arg.(*ast.CompositeLit)
	if isComp {
		return len(compLit.Elts)
	}

	// Check for a variable reference whose size was tracked from its assignment.
	ident, isIdent := arg.(*ast.Ident)
	if isIdent {
		scope := a.enclosingFunc(call.Pos(), ctx)
		if size, ok := ctx.varSizes[scope+":"+ident.Name]; ok {
			return size
		}
		// Fall back to package-level scope.
		if size, ok := ctx.varSizes[":"+ident.Name]; ok {
			return size
		}
	}

	return 0
}

// isWeakHashConstructor checks if an expression is sha1.New.
func (a *Analyzer) isWeakHashConstructor(expr ast.Expr, ctx *analysisContext) bool {
	sel, isSel := expr.(*ast.SelectorExpr)
	if !isSel {
		return false
	}

	importPath, ok := a.resolveSelector(sel, ctx)
	if !ok {
		return false
	}

	return importPath == "crypto/sha1" && sel.Sel.Name == "New"
}

// isMD5Constructor checks if an expression is md5.New.
func (a *Analyzer) isMD5Constructor(expr ast.Expr, ctx *analysisContext) bool {
	sel, isSel := expr.(*ast.SelectorExpr)
	if !isSel {
		return false
	}

	importPath, ok := a.resolveSelector(sel, ctx)
	if !ok {
		return false
	}

	return importPath == "crypto/md5" && sel.Sel.Name == "New"
}

// sanitizeID replaces characters unsuitable for IDs with hyphens.
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
