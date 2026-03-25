package spectral

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"quantumshield/pkg/models"
)

// MigrationPhase represents a single phase in the spectral partitioning result.
type MigrationPhase struct {
	Phase          int      `json:"phase"`
	Packages       []string `json:"packages"`
	CriticalCount  int      `json:"critical_count"`
	TotalFindings  int      `json:"total_findings"`
	CrossPhaseEdges int    `json:"cross_phase_edges"`
}

// PartitionResult contains the full output of graph spectral partitioning.
type PartitionResult struct {
	Phases         []MigrationPhase `json:"phases"`
	Laplacian      [][]float64      `json:"laplacian,omitempty"`
	FiedlerVector  []float64        `json:"fiedler_vector,omitempty"`
	NormalizedCutVal float64        `json:"normalized_cut"`
	NodeIndex      map[string]int   `json:"node_index"`
}

// PartitionOption is a functional option for configuring DependencyPartitioner.
type PartitionOption func(*DependencyPartitioner)

// WithMaxPhases sets the maximum number of migration phases.
func WithMaxPhases(n int) PartitionOption {
	return func(p *DependencyPartitioner) {
		p.maxPhases = n
	}
}

// WithMaxIterations sets the maximum power iteration count.
func WithMaxIterations(n int) PartitionOption {
	return func(p *DependencyPartitioner) {
		p.maxIterations = n
	}
}

// WithTolerance sets the convergence tolerance for eigenvector computation.
func WithTolerance(tol float64) PartitionOption {
	return func(p *DependencyPartitioner) {
		p.tolerance = tol
	}
}

// DependencyPartitioner uses spectral graph theory to partition a dependency
// graph into migration phases that minimize cross-phase dependencies.
type DependencyPartitioner struct {
	maxPhases     int
	maxIterations int
	tolerance     float64
}

// NewDependencyPartitioner creates a new partitioner with default settings,
// optionally modified by functional options.
func NewDependencyPartitioner(opts ...PartitionOption) *DependencyPartitioner {
	p := &DependencyPartitioner{
		maxPhases:     4,
		maxIterations: 1000,
		tolerance:     1e-10,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// BuildLaplacian constructs the graph Laplacian matrix L = D - W from a
// dependency graph. Edge weights are computed as the sum of crypto finding
// counts on both endpoints (minimum weight 1).
func BuildLaplacian(graph *models.DependencyGraph) (L [][]float64, nodeIndex map[string]int, indexNode map[int]string) {
	// Build a stable node ordering
	names := make([]string, 0, len(graph.Nodes))
	for name := range graph.Nodes {
		names = append(names, name)
	}
	sort.Strings(names)

	n := len(names)
	nodeIndex = make(map[string]int, n)
	indexNode = make(map[int]string, n)
	for i, name := range names {
		nodeIndex[name] = i
		indexNode[i] = name
	}

	// Build weighted adjacency matrix W
	W := make([][]float64, n)
	for i := range W {
		W[i] = make([]float64, n)
	}

	for name, node := range graph.Nodes {
		i := nodeIndex[name]
		for _, depName := range node.Dependencies {
			if _, exists := graph.Nodes[depName]; !exists {
				continue
			}
			j := nodeIndex[depName]
			if i == j {
				continue
			}
			// Weight = sum of crypto findings on both endpoints, minimum 1
			depNode := graph.Nodes[depName]
			weight := float64(len(node.CryptoFindings) + len(depNode.CryptoFindings))
			if weight < 1 {
				weight = 1
			}
			// Undirected: set both directions, taking maximum if already set
			if weight > W[i][j] {
				W[i][j] = weight
				W[j][i] = weight
			}
		}
	}

	// Build Laplacian L = D - W
	L = make([][]float64, n)
	for i := range L {
		L[i] = make([]float64, n)
		degree := 0.0
		for j := 0; j < n; j++ {
			degree += W[i][j]
			L[i][j] = -W[i][j]
		}
		L[i][i] = degree
	}

	return L, nodeIndex, indexNode
}

// ComputeFiedlerVector computes the Fiedler vector (eigenvector corresponding
// to the second-smallest eigenvalue) of the Laplacian matrix L.
// First finds lambda_1 (should be ~0 for connected graphs), then uses
// inverse power iteration with a shift to find the next eigenvalue/eigenvector.
func (p *DependencyPartitioner) ComputeFiedlerVector(L [][]float64) ([]float64, float64, error) {
	n := len(L)
	if n < 2 {
		return nil, 0, errors.New("matrix too small for Fiedler vector")
	}

	// Find lambda_1 (smallest eigenvalue, should be ~0 for connected graph)
	// Use inverse power iteration with shift=0 to find smallest eigenvalue
	_, lambda1, err := InversePowerIteration(L, 0.0, p.maxIterations, p.tolerance)
	if err != nil {
		// If singular (as expected for connected graph with lambda1=0),
		// assume lambda1 = 0
		lambda1 = 0.0
	}

	// Find lambda_2 using inverse power iteration with shift slightly above lambda_1
	// This finds the eigenvalue closest to the shift
	shift := lambda1 + 1e-6
	fiedler, lambda2, err := InversePowerIteration(L, shift, p.maxIterations, p.tolerance)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compute Fiedler vector: %w", err)
	}

	return fiedler, lambda2, nil
}

// Partition performs spectral graph partitioning on the dependency graph.
// It builds the Laplacian, computes a spectral embedding using the first k
// eigenvectors, clusters nodes via k-means, orders phases by critical finding
// count (descending), and computes cross-phase edge counts.
func (p *DependencyPartitioner) Partition(graph *models.DependencyGraph) (*PartitionResult, error) {
	if len(graph.Nodes) == 0 {
		return nil, errors.New("empty dependency graph")
	}

	// Single node: one phase
	if len(graph.Nodes) == 1 {
		var name string
		var node *models.DependencyNode
		for name, node = range graph.Nodes {
			break
		}
		critCount := 0
		for _, f := range node.CryptoFindings {
			if f.Severity == models.SeverityCritical {
				critCount++
			}
		}
		return &PartitionResult{
			Phases: []MigrationPhase{
				{
					Phase:          1,
					Packages:       []string{name},
					CriticalCount:  critCount,
					TotalFindings:  len(node.CryptoFindings),
					CrossPhaseEdges: 0,
				},
			},
			NodeIndex:        map[string]int{name: 0},
			NormalizedCutVal: 0,
		}, nil
	}

	L, nodeIndex, indexNode := BuildLaplacian(graph)
	n := len(L)

	// Determine number of phases (clusters)
	k := p.maxPhases
	if k > n {
		k = n
	}

	// Build spectral embedding: use the first k smallest non-trivial eigenvectors
	embedding := make([][]float64, n)
	for i := range embedding {
		embedding[i] = make([]float64, k)
	}

	// Compute eigenvectors using inverse power iteration with deflation-style shifts
	// Find eigenvalues in ascending order
	eigenvectors := make([][]float64, 0, k)
	eigenvalues := make([]float64, 0, k)

	// First eigenvector (lambda ~0): the constant vector, skip it
	// Start from the Fiedler vector onward
	for eidx := 0; eidx < k; eidx++ {
		// Use a shift that targets increasingly large eigenvalues
		shift := float64(eidx) * 0.5
		if eidx == 0 {
			shift = 1e-6 // Just above 0 to get Fiedler
		}
		v, _, err := InversePowerIteration(L, shift, p.maxIterations, p.tolerance)
		if err != nil {
			// Fallback: use available eigenvectors
			break
		}
		// Orthogonalize against previous eigenvectors (Gram-Schmidt)
		for _, prev := range eigenvectors {
			dot := VecDot(v, prev)
			for i := range v {
				v[i] -= dot * prev[i]
			}
		}
		norm := VecNorm(v)
		if norm < 1e-14 {
			continue
		}
		for i := range v {
			v[i] /= norm
		}
		eigenvectors = append(eigenvectors, v)
		eigenvalues = append(eigenvalues, shift)
	}

	actualK := len(eigenvectors)
	if actualK == 0 {
		// Fallback: put all nodes in one phase
		return p.singlePhaseResult(graph, L, nodeIndex)
	}

	// If we have fewer eigenvectors than desired clusters, reduce k
	if actualK < k {
		k = actualK
	}
	if k < 1 {
		k = 1
	}

	// Build embedding from eigenvectors
	for i := 0; i < n; i++ {
		row := make([]float64, actualK)
		for j := 0; j < actualK; j++ {
			row[j] = eigenvectors[j][i]
		}
		embedding[i] = row
	}

	// K-means clustering on the spectral embedding
	assignments, _, err := KMeans(embedding, k, 100)
	if err != nil {
		return p.singlePhaseResult(graph, L, nodeIndex)
	}

	// Build phases from cluster assignments
	phaseMap := make(map[int][]string)
	for i, cluster := range assignments {
		name := indexNode[i]
		phaseMap[cluster] = append(phaseMap[cluster], name)
	}

	phases := make([]MigrationPhase, 0, len(phaseMap))
	for _, packages := range phaseMap {
		critCount := 0
		totalFindings := 0
		for _, pkg := range packages {
			node := graph.Nodes[pkg]
			totalFindings += len(node.CryptoFindings)
			for _, f := range node.CryptoFindings {
				if f.Severity == models.SeverityCritical {
					critCount++
				}
			}
		}
		sort.Strings(packages)
		phases = append(phases, MigrationPhase{
			Packages:      packages,
			CriticalCount: critCount,
			TotalFindings: totalFindings,
		})
	}

	// Order phases by critical finding count descending
	sort.Slice(phases, func(i, j int) bool {
		if phases[i].CriticalCount != phases[j].CriticalCount {
			return phases[i].CriticalCount > phases[j].CriticalCount
		}
		return phases[i].TotalFindings > phases[j].TotalFindings
	})

	// Assign phase numbers and compute cross-phase edges
	nodePhase := make(map[string]int)
	for i := range phases {
		phases[i].Phase = i + 1
		for _, pkg := range phases[i].Packages {
			nodePhase[pkg] = i + 1
		}
	}

	for i := range phases {
		crossEdges := 0
		for _, pkg := range phases[i].Packages {
			node := graph.Nodes[pkg]
			for _, dep := range node.Dependencies {
				if depPhase, ok := nodePhase[dep]; ok && depPhase != phases[i].Phase {
					crossEdges++
				}
			}
		}
		phases[i].CrossPhaseEdges = crossEdges
	}

	// Compute Fiedler vector for the result
	var fiedler []float64
	if len(eigenvectors) > 0 {
		fiedler = eigenvectors[0]
	}

	// Compute normalized cut for the best 2-way partition (Fiedler-based)
	ncut := 0.0
	if len(phases) >= 2 && fiedler != nil {
		ncut = p.computeNCutFromPartition(graph, nodePhase, L, nodeIndex)
	}

	return &PartitionResult{
		Phases:           phases,
		Laplacian:        L,
		FiedlerVector:    fiedler,
		NormalizedCutVal: ncut,
		NodeIndex:        nodeIndex,
	}, nil
}

// singlePhaseResult creates a result with all nodes in one phase.
func (p *DependencyPartitioner) singlePhaseResult(graph *models.DependencyGraph, L [][]float64, nodeIndex map[string]int) (*PartitionResult, error) {
	packages := make([]string, 0, len(graph.Nodes))
	critCount := 0
	totalFindings := 0
	for name, node := range graph.Nodes {
		packages = append(packages, name)
		totalFindings += len(node.CryptoFindings)
		for _, f := range node.CryptoFindings {
			if f.Severity == models.SeverityCritical {
				critCount++
			}
		}
	}
	sort.Strings(packages)
	return &PartitionResult{
		Phases: []MigrationPhase{
			{
				Phase:           1,
				Packages:        packages,
				CriticalCount:   critCount,
				TotalFindings:   totalFindings,
				CrossPhaseEdges: 0,
			},
		},
		Laplacian: L,
		NodeIndex: nodeIndex,
	}, nil
}

// computeNCutFromPartition computes the normalized cut across all phase pairs.
func (p *DependencyPartitioner) computeNCutFromPartition(graph *models.DependencyGraph, nodePhase map[string]int, L [][]float64, nodeIndex map[string]int) float64 {
	// Collect all distinct phases
	phaseSet := make(map[int]bool)
	for _, ph := range nodePhase {
		phaseSet[ph] = true
	}
	if len(phaseSet) < 2 {
		return 0
	}

	// Compute volume of each phase (sum of degrees)
	phaseVol := make(map[int]float64)
	for name, ph := range nodePhase {
		idx := nodeIndex[name]
		phaseVol[ph] += L[idx][idx] // diagonal = degree
	}

	// Compute cut between all phase pairs
	totalNCut := 0.0
	phases := make([]int, 0, len(phaseSet))
	for ph := range phaseSet {
		phases = append(phases, ph)
	}
	sort.Ints(phases)

	for i := 0; i < len(phases); i++ {
		for j := i + 1; j < len(phases); j++ {
			cutVal := 0.0
			for name, node := range graph.Nodes {
				ph1 := nodePhase[name]
				if ph1 != phases[i] {
					continue
				}
				for _, dep := range node.Dependencies {
					if ph2, ok := nodePhase[dep]; ok && ph2 == phases[j] {
						// Count the edge weight
						ni := nodeIndex[name]
						nj := nodeIndex[dep]
						cutVal += math.Abs(L[ni][nj]) // off-diagonal = -weight, so abs
					}
				}
			}
			volA := phaseVol[phases[i]]
			volB := phaseVol[phases[j]]
			if volA > 0 && volB > 0 {
				totalNCut += cutVal/volA + cutVal/volB
			}
		}
	}

	return totalNCut
}

// NormalizedCut computes NCut(A,B) = cut(A,B)/vol(A) + cut(A,B)/vol(B)
// for a binary partition defined by sets A and B over a weighted adjacency
// described by the Laplacian L. A and B are specified as sets of node indices.
func NormalizedCut(L [][]float64, A, B []int) float64 {
	aSet := make(map[int]bool, len(A))
	for _, i := range A {
		aSet[i] = true
	}
	bSet := make(map[int]bool, len(B))
	for _, i := range B {
		bSet[i] = true
	}

	// Compute cut(A,B): sum of edge weights between A and B
	cutAB := 0.0
	for _, i := range A {
		for _, j := range B {
			// L[i][j] = -w(i,j) for i != j
			cutAB += math.Abs(L[i][j])
		}
	}

	// Compute vol(A): sum of degrees of nodes in A
	volA := 0.0
	for _, i := range A {
		volA += L[i][i] // diagonal = degree
	}

	// Compute vol(B): sum of degrees of nodes in B
	volB := 0.0
	for _, i := range B {
		volB += L[i][i] // diagonal = degree
	}

	if volA == 0 || volB == 0 {
		return math.Inf(1)
	}

	return cutAB/volA + cutAB/volB
}
