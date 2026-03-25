package models

// DependencyNode represents a single package in the dependency graph.
type DependencyNode struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	Language       string    `json:"language"`
	Dependencies   []string  `json:"dependencies"`
	CryptoFindings []Finding `json:"crypto_findings"`
}

// DependencyGraph represents the full dependency tree of a project.
type DependencyGraph struct {
	Nodes       map[string]*DependencyNode `json:"nodes"`
	RootPackage string                     `json:"root_package"`
}
