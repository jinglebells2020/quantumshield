package taint

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quantumshield/pkg/models"
)

// TaintLabel tracks the origin of a tainted value.
type TaintLabel struct {
	Algorithm  string  // "RSA-2048", "DES", "MD5", etc.
	Source     string  // "rsa.GenerateKey", "string literal", etc.
	SourceFile string
	SourceLine int
	Confidence float64 // Decreases with propagation depth: 0.95^depth
}

// TaintedValue represents a variable carrying tainted crypto data.
type TaintedValue struct {
	VarName   string
	Package   string
	Labels    []TaintLabel
	PropDepth int
}

// FuncNode represents a function in the call graph.
type FuncNode struct {
	Name    string
	Package string
	File    string
	Params  []string // parameter names
	Returns int      // number of return values
	Decl    *ast.FuncDecl
}

// CallGraph maps functions to their callees.
type CallGraph struct {
	Nodes map[string]*FuncNode // "pkg.Func" -> node
	Edges map[string][]string  // "pkg.Caller" -> ["pkg.Callee1", ...]
}

// TaintEngine performs cross-file taint analysis.
type TaintEngine struct {
	fset       *token.FileSet
	packages   map[string]*ast.Package  // pkgName -> parsed package
	graph      CallGraph
	taintState map[string][]TaintedValue // funcKey -> tainted values
	maxDepth   int
	cache      map[string]bool
	findings   []models.Finding
}

// cryptoSources maps function calls to their taint labels.
var cryptoSources = map[string]string{
	"rsa.GenerateKey":        "RSA",
	"ecdsa.GenerateKey":      "ECDSA",
	"ecdh.GenerateKey":       "ECDH",
	"ecdh.P256":              "ECDH-P256",
	"ecdh.P384":              "ECDH-P384",
	"ecdh.X25519":            "ECDH-X25519",
	"elliptic.P256":          "ECDSA-P256",
	"elliptic.P384":          "ECDSA-P384",
	"elliptic.P521":          "ECDSA-P521",
	"aes.NewCipher":          "AES",
	"des.NewCipher":          "DES",
	"des.NewTripleDESCipher": "3DES",
	"rc4.NewCipher":          "RC4",
	"md5.New":                "MD5",
	"sha1.New":               "SHA-1",
	"x509.CreateCertificate": "X.509",
}

// algorithmStrings maps string literals to algorithm names.
var algorithmStrings = map[string]string{
	"DES": "DES", "DESede": "3DES", "3DES": "3DES",
	"RSA": "RSA", "DSA": "DSA",
	"MD5": "MD5", "MD2": "MD2",
	"SHA1": "SHA-1", "SHA-1": "SHA-1",
	"AES": "AES", "Blowfish": "Blowfish", "RC4": "RC4",
}

// New creates a new TaintEngine.
func New(maxDepth int) *TaintEngine {
	if maxDepth <= 0 {
		maxDepth = 5
	}
	return &TaintEngine{
		fset:       token.NewFileSet(),
		packages:   make(map[string]*ast.Package),
		graph:      CallGraph{Nodes: make(map[string]*FuncNode), Edges: make(map[string][]string)},
		taintState: make(map[string][]TaintedValue),
		maxDepth:   maxDepth,
		cache:      make(map[string]bool),
	}
}

// AnalyzeDirectory performs cross-file taint analysis on all Go files in a directory tree.
func (te *TaintEngine) AnalyzeDirectory(ctx context.Context, root string) ([]models.Finding, error) {
	te.findings = nil

	// Phase A: Parse all Go files
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "node_modules" || base == ".git" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(te.fset, path, nil, parser.AllErrors)
		if parseErr != nil {
			return nil
		}

		pkgName := f.Name.Name
		if te.packages[pkgName] == nil {
			te.packages[pkgName] = &ast.Package{Name: pkgName, Files: make(map[string]*ast.File)}
		}
		te.packages[pkgName].Files[path] = f
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Phase B: Build call graph
	te.buildCallGraph()

	// Phase C: Find taint sources and propagate
	te.findTaintSources()
	te.propagateTaint(0)

	return te.findings, nil
}

func (te *TaintEngine) buildCallGraph() {
	// Pass 1: Register all function nodes so qualifyCallName can resolve them.
	for pkgName, pkg := range te.packages {
		for filePath, file := range pkg.Files {
			for _, decl := range file.Decls {
				funcDecl, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}

				funcKey := pkgName + "." + funcDecl.Name.Name
				var params []string
				if funcDecl.Type.Params != nil {
					for _, p := range funcDecl.Type.Params.List {
						for _, name := range p.Names {
							params = append(params, name.Name)
						}
					}
				}
				returns := 0
				if funcDecl.Type.Results != nil {
					returns = len(funcDecl.Type.Results.List)
				}

				te.graph.Nodes[funcKey] = &FuncNode{
					Name:    funcDecl.Name.Name,
					Package: pkgName,
					File:    filePath,
					Params:  params,
					Returns: returns,
					Decl:    funcDecl,
				}
			}
		}
	}

	// Pass 2: Resolve edges now that all nodes are registered.
	for pkgName, pkg := range te.packages {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				funcDecl, ok := decl.(*ast.FuncDecl)
				if !ok || funcDecl.Body == nil {
					continue
				}

				funcKey := pkgName + "." + funcDecl.Name.Name
				currentPkg := pkgName
				ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					calleeName := resolveCallName(call)
					if calleeName != "" {
						qualified := te.qualifyCallName(calleeName, currentPkg)
						te.graph.Edges[funcKey] = append(te.graph.Edges[funcKey], qualified)
					}
					return true
				})
			}
		}
	}
}

func (te *TaintEngine) findTaintSources() {
	for pkgName, pkg := range te.packages {
		for filePath, file := range pkg.Files {
			for _, decl := range file.Decls {
				funcDecl, ok := decl.(*ast.FuncDecl)
				if !ok || funcDecl.Body == nil {
					continue
				}

				funcKey := pkgName + "." + funcDecl.Name.Name

				ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
					switch node := n.(type) {
					case *ast.AssignStmt:
						te.processAssignment(node, funcKey, pkgName, filePath)
					case *ast.CallExpr:
						// Check if a tainted value is passed as argument to a crypto sink
						callName := resolveCallName(node)
						te.checkTaintSink(funcKey, callName, node, filePath)
					}
					return true
				})
			}
		}
	}
}

func (te *TaintEngine) processAssignment(node *ast.AssignStmt, funcKey, pkgName, filePath string) {
	for i, rhs := range node.Rhs {
		// Check RHS for crypto source function calls
		if call, ok := rhs.(*ast.CallExpr); ok {
			callName := resolveCallName(call)
			if algo, isCrypto := cryptoSources[callName]; isCrypto {
				if i < len(node.Lhs) {
					if ident, ok := node.Lhs[i].(*ast.Ident); ok {
						pos := te.fset.Position(node.Pos())
						te.taintState[funcKey] = append(te.taintState[funcKey], TaintedValue{
							VarName: ident.Name,
							Package: pkgName,
							Labels: []TaintLabel{{
								Algorithm:  algo,
								Source:     callName,
								SourceFile: filePath,
								SourceLine: pos.Line,
								Confidence: 0.95,
							}},
							PropDepth: 0,
						})
					}
				}
			}
		}
		// Check for algorithm string literals
		if lit, ok := rhs.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			val := strings.Trim(lit.Value, `"`)
			if algo, known := algorithmStrings[val]; known {
				if i < len(node.Lhs) {
					if ident, ok := node.Lhs[i].(*ast.Ident); ok {
						pos := te.fset.Position(node.Pos())
						te.taintState[funcKey] = append(te.taintState[funcKey], TaintedValue{
							VarName: ident.Name,
							Package: pkgName,
							Labels: []TaintLabel{{
								Algorithm:  algo,
								Source:     "string literal",
								SourceFile: filePath,
								SourceLine: pos.Line,
								Confidence: 0.90,
							}},
							PropDepth: 0,
						})
					}
				}
			}
		}
		// Propagate taint through local assignment: if RHS is a tainted variable,
		// the LHS becomes tainted too.
		if ident, ok := rhs.(*ast.Ident); ok {
			for _, tv := range te.taintState[funcKey] {
				if tv.VarName == ident.Name {
					if i < len(node.Lhs) {
						if lhsIdent, ok := node.Lhs[i].(*ast.Ident); ok {
							newLabels := make([]TaintLabel, len(tv.Labels))
							copy(newLabels, tv.Labels)
							newTV := TaintedValue{
								VarName:   lhsIdent.Name,
								Package:   tv.Package,
								Labels:    newLabels,
								PropDepth: tv.PropDepth,
							}
							if !te.hasTaint(funcKey, newTV) {
								te.taintState[funcKey] = append(te.taintState[funcKey], newTV)
							}
						}
					}
				}
			}
		}
	}
}

func (te *TaintEngine) propagateTaint(depth int) {
	if depth >= te.maxDepth {
		return
	}

	changed := false
	for callerKey, callees := range te.graph.Edges {
		callerTaint := te.taintState[callerKey]
		if len(callerTaint) == 0 {
			continue
		}

		for _, calleeKey := range callees {
			calleeNode := te.graph.Nodes[calleeKey]
			if calleeNode == nil {
				continue
			}

			// Propagate taint through function parameters
			callerNode := te.graph.Nodes[callerKey]
			if callerNode == nil || callerNode.Decl == nil || callerNode.Decl.Body == nil {
				continue
			}

			callerPkg := callerNode.Package
			ast.Inspect(callerNode.Decl.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				rawName := resolveCallName(call)
				qualifiedName := te.qualifyCallName(rawName, callerPkg)
				if qualifiedName != calleeKey {
					return true
				}

				for i, arg := range call.Args {
					argIdent, ok := arg.(*ast.Ident)
					if !ok {
						continue
					}
					for _, tv := range callerTaint {
						if tv.VarName == argIdent.Name && tv.PropDepth < te.maxDepth {
							if i < len(calleeNode.Params) {
								newLabels := make([]TaintLabel, len(tv.Labels))
								for j, l := range tv.Labels {
									newLabels[j] = l
									newLabels[j].Confidence *= 0.95
								}
								newTV := TaintedValue{
									VarName:   calleeNode.Params[i],
									Package:   calleeNode.Package,
									Labels:    newLabels,
									PropDepth: tv.PropDepth + 1,
								}
								if !te.hasTaint(calleeKey, newTV) {
									te.taintState[calleeKey] = append(te.taintState[calleeKey], newTV)
									changed = true
								}
							}
						}
					}
				}
				return true
			})
		}
	}

	// Check for taint sinks after propagation
	for funcKey, taints := range te.taintState {
		if len(taints) == 0 {
			continue
		}
		node := te.graph.Nodes[funcKey]
		if node == nil || node.Decl == nil || node.Decl.Body == nil {
			continue
		}

		ast.Inspect(node.Decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callName := resolveCallName(call)
			te.checkTaintSink(funcKey, callName, call, node.File)
			return true
		})
	}

	if changed {
		te.propagateTaint(depth + 1)
	}
}

// sinks lists functions that consume crypto values and represent taint sinks.
var sinks = map[string]bool{
	"cipher.NewGCM":          true,
	"cipher.NewCBCEncrypter": true,
	"cipher.NewCBCDecrypter": true,
	"cipher.NewCFBEncrypter": true,
	"cipher.NewCFBDecrypter": true,
	"rsa.EncryptOAEP":        true,
	"rsa.DecryptOAEP":        true,
	"rsa.SignPSS":            true,
	"rsa.SignPKCS1v15":       true,
	"ecdsa.Sign":             true,
	"ecdsa.SignASN1":         true,
	"tls.NewListener":        true,
	"tls.Dial":               true,
	"x509.CreateCertificate": true,
	"hmac.New":               true,
}

func (te *TaintEngine) checkTaintSink(funcKey, callName string, call *ast.CallExpr, filePath string) {
	if !sinks[callName] {
		return
	}

	// Check if any argument is tainted
	taints := te.taintState[funcKey]
	for _, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if !ok {
			continue
		}
		for _, tv := range taints {
			if tv.VarName == ident.Name {
				for _, label := range tv.Labels {
					pos := te.fset.Position(call.Pos())
					findingID := fmt.Sprintf("taint-%s-%d-%s", filepath.Base(filePath), pos.Line, label.Algorithm)

					if te.cache[findingID] {
						continue
					}
					te.cache[findingID] = true

					severity := models.SeverityCritical
					threat := models.ThreatBrokenByShor
					category := models.CategoryAsymmetricEncryption

					switch {
					case strings.Contains(label.Algorithm, "AES"):
						severity = models.SeverityMedium
						threat = models.ThreatWeakenedByGrover
						category = models.CategorySymmetricEncryption
					case strings.Contains(label.Algorithm, "MD5") || strings.Contains(label.Algorithm, "SHA-1"):
						severity = models.SeverityHigh
						threat = models.ThreatWeakenedByGrover
						category = models.CategoryHashing
					case strings.Contains(label.Algorithm, "DES") || strings.Contains(label.Algorithm, "RC4"):
						severity = models.SeverityCritical
						threat = models.ThreatWeakenedByGrover
						category = models.CategorySymmetricEncryption
					}

					te.findings = append(te.findings, models.Finding{
						ID:            findingID,
						RuleID:        "QS-TAINT-001",
						Severity:      severity,
						Category:      category,
						QuantumThreat: threat,
						FilePath:      filePath,
						LineStart:     pos.Line,
						LineEnd:       pos.Line,
						ColumnStart:   pos.Column,
						Algorithm:     label.Algorithm,
						Usage:         "cross-file taint: " + label.Source,
						Library:       callName,
						Language:      "go",
						Description: fmt.Sprintf(
							"Cross-file taint: %s value from %s:%d flows to %s at %s:%d",
							label.Algorithm,
							filepath.Base(label.SourceFile), label.SourceLine,
							callName,
							filepath.Base(filePath), pos.Line,
						),
						Confidence: label.Confidence,
						CreatedAt:  time.Now(),
					})
				}
			}
		}
	}
}

func (te *TaintEngine) hasTaint(funcKey string, tv TaintedValue) bool {
	for _, existing := range te.taintState[funcKey] {
		if existing.VarName == tv.VarName && existing.Package == tv.Package {
			return true
		}
	}
	return false
}

// qualifyCallName normalises a call name. If the name has no dot (a bare
// function call within the same package) and a node with "pkg.Name" exists
// in the call graph, return the qualified form. Otherwise return as-is.
func (te *TaintEngine) qualifyCallName(name, currentPkg string) string {
	if name == "" {
		return ""
	}
	// Already qualified (selector expression like "rsa.GenerateKey").
	if strings.Contains(name, ".") {
		return name
	}
	// Bare name -- qualify with the current package.
	qualified := currentPkg + "." + name
	if _, ok := te.graph.Nodes[qualified]; ok {
		return qualified
	}
	return name
}

func resolveCallName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
	case *ast.Ident:
		return fn.Name
	}
	return ""
}
