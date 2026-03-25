package tda

import (
	"fmt"
	"math"
	"sort"

	"quantumshield/pkg/models"
)

// PersistencePair records the birth and death of a topological feature
// (connected component) in the Vietoris-Rips filtration.
type PersistencePair struct {
	Birth       float64  `json:"birth"`
	Death       float64  `json:"death"`
	Persistence float64  `json:"persistence"`
	Dimension   int      `json:"dimension"`
	Members     []string `json:"members"`
}

// VulnCluster represents a stable cluster of cryptographic findings identified
// by the persistence analysis.
type VulnCluster struct {
	ClusterID    int       `json:"cluster_id"`
	FindingIDs   []string  `json:"finding_ids"`
	Persistence  float64   `json:"persistence"`
	CenterOfMass []float64 `json:"center_of_mass"`
	Description  string    `json:"description"`
}

// PersistenceResult holds the complete output of a TDA persistence analysis.
type PersistenceResult struct {
	Pairs              []PersistencePair `json:"pairs"`
	StableClusters     []VulnCluster     `json:"stable_clusters"`
	IsolatedFindings   []string          `json:"isolated_findings"`
	PersistenceEntropy float64           `json:"persistence_entropy"`
	TopFeatures        []string          `json:"top_features"`
}

// TDAOption is a functional option for configuring the PersistenceAnalyzer.
type TDAOption func(*PersistenceAnalyzer)

// WithPersistenceThreshold sets the minimum persistence value for a cluster
// to be considered stable.
func WithPersistenceThreshold(t float64) TDAOption {
	return func(p *PersistenceAnalyzer) { p.persistenceThreshold = t }
}

// PersistenceAnalyzer computes 0-dimensional persistent homology on
// embedded vulnerability findings.
type PersistenceAnalyzer struct {
	persistenceThreshold float64
}

// NewPersistenceAnalyzer creates a PersistenceAnalyzer with the given options.
func NewPersistenceAnalyzer(opts ...TDAOption) *PersistenceAnalyzer {
	pa := &PersistenceAnalyzer{
		persistenceThreshold: 0.3,
	}
	for _, o := range opts {
		o(pa)
	}
	return pa
}

// algorithmFamilies defines the one-hot encoding order for algorithm categories.
var algorithmFamilies = []models.AlgorithmCategory{
	models.CategoryAsymmetricEncryption,
	models.CategoryDigitalSignature,
	models.CategoryKeyExchange,
	models.CategorySymmetricEncryption,
	models.CategoryHashing,
	models.CategoryKeyDerivation,
	models.CategoryTLSCipherSuite,
	models.CategoryCertificate,
	models.CategorySSH,
	models.CategoryKMS,
}

// EmbedFindings maps each Finding to a numeric feature vector suitable for
// distance computation. The vector components are:
//
//	[0] severity_normalized        (0=critical..3=low) / 3.0
//	[1] quantum_threat_normalized  (0=shor..2=safe) / 2.0
//	[2] data_sensitivity           0.0 or 1.0
//	[3] in_dependency              0.0 or 1.0
//	[4] dep_depth                  len(DependencyChain) / 10.0, capped at 1.0
//	[5] confidence                 Finding.Confidence
//	[6] file_proximity             hash(FilePath) mod 1.0 (simple proxy)
//	[7..7+N-1] algorithm_family_onehot  one-hot for category
func EmbedFindings(findings []models.Finding) [][]float64 {
	numAlgoFamilies := len(algorithmFamilies)
	dim := 7 + numAlgoFamilies
	vectors := make([][]float64, len(findings))

	for i, f := range findings {
		v := make([]float64, dim)

		// Severity normalized: Critical=0 -> 1.0, Low=3 -> 0.0
		v[0] = 1.0 - float64(f.Severity)/3.0

		// Quantum threat normalized: Shor=0 -> 1.0, Safe=2 -> 0.0
		v[1] = 1.0 - float64(f.QuantumThreat)/2.0

		// Data sensitivity: binary
		if f.DataSensitivity != "" {
			v[2] = 1.0
		}

		// In dependency
		if f.InDependency {
			v[3] = 1.0
		}

		// Dependency chain depth, normalized and capped
		depDepth := float64(len(f.DependencyChain)) / 10.0
		if depDepth > 1.0 {
			depDepth = 1.0
		}
		v[4] = depDepth

		// Confidence
		v[5] = f.Confidence

		// File proximity: simple hash-based proxy for grouping files
		v[6] = fileProximityHash(f.FilePath)

		// One-hot encoding for algorithm category
		for j, cat := range algorithmFamilies {
			if f.Category == cat {
				v[7+j] = 1.0
			}
		}

		vectors[i] = v
	}
	return vectors
}

// FeatureDimension returns the dimensionality of the embedding vectors.
func FeatureDimension() int {
	return 7 + len(algorithmFamilies)
}

// fileProximityHash produces a value in [0,1) from a file path string. Files
// with the same path get the same value; similar paths may get nearby values.
func fileProximityHash(path string) float64 {
	if path == "" {
		return 0
	}
	h := uint64(0)
	for _, c := range path {
		h = h*31 + uint64(c)
	}
	return float64(h%10000) / 10000.0
}

// edgeEntry is an internal type for sorted edge processing.
type edgeEntry struct {
	i, j int
	dist float64
}

// ComputePersistence runs the 0-dimensional persistent homology computation.
// It:
//  1. Embeds findings into feature vectors.
//  2. Computes pairwise distances.
//  3. Sorts edges by distance (Vietoris-Rips filtration).
//  4. Processes edges via Union-Find, recording birth-death pairs.
//  5. Identifies stable clusters (persistence > threshold) and isolated findings.
func (pa *PersistenceAnalyzer) ComputePersistence(findings []models.Finding) (*PersistenceResult, error) {
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings to analyze")
	}
	if len(findings) == 1 {
		return &PersistenceResult{
			Pairs: nil,
			StableClusters: []VulnCluster{{
				ClusterID:  0,
				FindingIDs: []string{findings[0].ID},
				Persistence: math.Inf(1),
				CenterOfMass: EmbedFindings(findings)[0],
				Description: fmt.Sprintf("single finding: %s", findings[0].Algorithm),
			}},
			IsolatedFindings:   []string{findings[0].ID},
			PersistenceEntropy: 0,
			TopFeatures:        []string{"single finding"},
		}, nil
	}

	// Step 1: embed
	vectors := EmbedFindings(findings)
	n := len(vectors)

	// Step 2: pairwise distances and build edge list
	var edges []edgeEntry
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			d := EuclideanDistance(vectors[i], vectors[j])
			edges = append(edges, edgeEntry{i: i, j: j, dist: d})
		}
	}

	// Step 3: sort edges by distance
	sort.Slice(edges, func(a, b int) bool {
		return edges[a].dist < edges[b].dist
	})

	// Step 4: Union-Find to track component merges
	uf := NewUnionFind(n)
	var pairs []PersistencePair

	for _, e := range edges {
		root, absorbed, merged := uf.Union(e.i, e.j)
		if !merged {
			continue
		}
		_ = root

		// The absorbed component dies at this edge distance
		birth := uf.birth[absorbed]
		death := e.dist
		persistence := death - birth

		// Collect member IDs of the absorbed component at time of death
		// (the members that were in the absorbed root's component)
		var members []string
		members = append(members, findings[absorbed].ID)

		pairs = append(pairs, PersistencePair{
			Birth:       birth,
			Death:       death,
			Persistence: persistence,
			Dimension:   0,
			Members:     members,
		})
	}

	// Sort pairs by persistence descending for analysis
	sort.Slice(pairs, func(a, b int) bool {
		return pairs[a].Persistence > pairs[b].Persistence
	})

	// Step 5: identify stable clusters
	// Re-run union-find but stop at the persistence threshold to extract clusters
	stableClusters, isolatedIDs := pa.extractClusters(findings, vectors, edges)

	// Compute persistence entropy
	entropy := PersistenceEntropy(pairs)

	// Top features: describe the most persistent pairs
	var topFeatures []string
	maxTop := 5
	if len(pairs) < maxTop {
		maxTop = len(pairs)
	}
	for i := 0; i < maxTop; i++ {
		topFeatures = append(topFeatures,
			fmt.Sprintf("component merge at d=%.3f (persistence=%.3f)",
				pairs[i].Death, pairs[i].Persistence))
	}

	return &PersistenceResult{
		Pairs:              pairs,
		StableClusters:     stableClusters,
		IsolatedFindings:   isolatedIDs,
		PersistenceEntropy: entropy,
		TopFeatures:        topFeatures,
	}, nil
}

// extractClusters re-runs the filtration and stops merging when the edge
// distance exceeds a cutoff derived from the persistence threshold. The
// remaining connected components are the stable clusters.
func (pa *PersistenceAnalyzer) extractClusters(
	findings []models.Finding,
	vectors [][]float64,
	edges []edgeEntry,
) ([]VulnCluster, []string) {
	n := len(findings)
	uf := NewUnionFind(n)

	// Find a good cutoff: use the persistence threshold as a fraction of the
	// maximum edge distance.
	maxDist := 0.0
	if len(edges) > 0 {
		maxDist = edges[len(edges)-1].dist
	}
	cutoff := maxDist * pa.persistenceThreshold

	for _, e := range edges {
		if e.dist > cutoff {
			break
		}
		uf.Union(e.i, e.j)
	}

	// Group findings by their root
	groups := make(map[int][]int)
	for i := 0; i < n; i++ {
		root := uf.Find(i)
		groups[root] = append(groups[root], i)
	}

	var clusters []VulnCluster
	var isolatedIDs []string
	clusterID := 0

	for _, members := range groups {
		ids := make([]string, len(members))
		for i, m := range members {
			ids[i] = findings[m].ID
		}

		// Compute center of mass
		dim := len(vectors[0])
		center := make([]float64, dim)
		for _, m := range members {
			for d := 0; d < dim; d++ {
				center[d] += vectors[m][d]
			}
		}
		for d := 0; d < dim; d++ {
			center[d] /= float64(len(members))
		}

		// Compute cluster persistence: max intra-cluster distance
		clusterPersistence := 0.0
		for i := 0; i < len(members); i++ {
			for j := i + 1; j < len(members); j++ {
				d := EuclideanDistance(vectors[members[i]], vectors[members[j]])
				if d > clusterPersistence {
					clusterPersistence = d
				}
			}
		}

		if len(members) == 1 {
			isolatedIDs = append(isolatedIDs, ids[0])
		}

		desc := describeCluster(findings, members)
		clusters = append(clusters, VulnCluster{
			ClusterID:    clusterID,
			FindingIDs:   ids,
			Persistence:  clusterPersistence,
			CenterOfMass: center,
			Description:  desc,
		})
		clusterID++
	}

	// Sort clusters by number of members descending
	sort.Slice(clusters, func(a, b int) bool {
		return len(clusters[a].FindingIDs) > len(clusters[b].FindingIDs)
	})

	return clusters, isolatedIDs
}

// describeCluster generates a human-readable summary of a cluster.
func describeCluster(findings []models.Finding, memberIdxs []int) string {
	if len(memberIdxs) == 0 {
		return "empty cluster"
	}

	// Count categories and threat levels
	catCount := make(map[models.AlgorithmCategory]int)
	threatCount := make(map[models.QuantumThreatLevel]int)
	for _, idx := range memberIdxs {
		catCount[findings[idx].Category]++
		threatCount[findings[idx].QuantumThreat]++
	}

	// Find dominant category
	var domCat models.AlgorithmCategory
	domCatN := 0
	for cat, n := range catCount {
		if n > domCatN {
			domCat = cat
			domCatN = n
		}
	}

	// Find dominant threat
	var domThreat models.QuantumThreatLevel
	domThreatN := 0
	for t, n := range threatCount {
		if n > domThreatN {
			domThreat = t
			domThreatN = n
		}
	}

	return fmt.Sprintf("%d findings, primarily %s (%s threat)",
		len(memberIdxs), domCat.String(), domThreat.String())
}

// PersistenceEntropy computes the Shannon entropy of the persistence diagram,
// normalized by total persistence. H = -sum(p_i/L * log(p_i/L)) where L is
// the sum of all persistence values.
func PersistenceEntropy(pairs []PersistencePair) float64 {
	if len(pairs) == 0 {
		return 0
	}

	totalL := 0.0
	for _, p := range pairs {
		if p.Persistence > 0 && !math.IsInf(p.Persistence, 0) {
			totalL += p.Persistence
		}
	}
	if totalL == 0 {
		return 0
	}

	entropy := 0.0
	for _, p := range pairs {
		if p.Persistence > 0 && !math.IsInf(p.Persistence, 0) {
			ratio := p.Persistence / totalL
			if ratio > 0 {
				entropy -= ratio * math.Log(ratio)
			}
		}
	}
	return entropy
}
