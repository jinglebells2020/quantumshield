package tda

import (
	"fmt"
	"math"
	"testing"

	"quantumshield/pkg/models"
)

func almostEqual(a, b, tol float64) bool {
	return math.Abs(a-b) < tol
}

// ---------- simplicial.go tests ----------

func TestUnionFind_Basic(t *testing.T) {
	uf := NewUnionFind(5)

	// Initially all elements are their own representative
	for i := 0; i < 5; i++ {
		if uf.Find(i) != i {
			t.Errorf("Find(%d) = %d, want %d", i, uf.Find(i), i)
		}
		if uf.Size(i) != 1 {
			t.Errorf("Size(%d) = %d, want 1", i, uf.Size(i))
		}
	}

	// Merge 0 and 1
	root, absorbed, merged := uf.Union(0, 1)
	if !merged {
		t.Error("Union(0,1) should merge")
	}
	if uf.Find(0) != uf.Find(1) {
		t.Error("0 and 1 should be in the same set")
	}
	_ = root
	_ = absorbed

	// Merge 2 and 3
	_, _, merged = uf.Union(2, 3)
	if !merged {
		t.Error("Union(2,3) should merge")
	}
	if uf.Find(2) != uf.Find(3) {
		t.Error("2 and 3 should be in the same set")
	}

	// 0 and 2 should be in different sets
	if uf.Find(0) == uf.Find(2) {
		t.Error("0 and 2 should be in different sets")
	}

	// Merge the two groups
	_, _, merged = uf.Union(1, 3)
	if !merged {
		t.Error("Union(1,3) should merge the groups")
	}
	// Now 0,1,2,3 should all share a root
	r := uf.Find(0)
	for i := 1; i <= 3; i++ {
		if uf.Find(i) != r {
			t.Errorf("Find(%d) = %d, want %d", i, uf.Find(i), r)
		}
	}
	if uf.Size(0) != 4 {
		t.Errorf("Size after merging 4 elements = %d, want 4", uf.Size(0))
	}

	// 4 is still isolated
	if uf.Find(4) != 4 {
		t.Errorf("Find(4) = %d, want 4", uf.Find(4))
	}

	// Union of same set should not merge
	_, _, merged = uf.Union(0, 1)
	if merged {
		t.Error("Union(0,1) should not merge (already same set)")
	}
}

func TestPairwiseDistances_Known(t *testing.T) {
	// Three points forming a right triangle: (0,0), (3,0), (0,4)
	points := [][]float64{
		{0, 0},
		{3, 0},
		{0, 4},
	}
	dist := PairwiseDistances(points)

	if len(dist) != 3 {
		t.Fatalf("expected 3x3 distance matrix, got %dx%d", len(dist), len(dist[0]))
	}

	// d(0,1) = 3
	if !almostEqual(dist[0][1], 3.0, 1e-9) {
		t.Errorf("d(0,1) = %f, want 3.0", dist[0][1])
	}
	// d(0,2) = 4
	if !almostEqual(dist[0][2], 4.0, 1e-9) {
		t.Errorf("d(0,2) = %f, want 4.0", dist[0][2])
	}
	// d(1,2) = 5 (hypotenuse)
	if !almostEqual(dist[1][2], 5.0, 1e-9) {
		t.Errorf("d(1,2) = %f, want 5.0", dist[1][2])
	}
	// Symmetry
	if !almostEqual(dist[0][1], dist[1][0], 1e-9) {
		t.Error("distance matrix should be symmetric")
	}
	// Diagonal = 0
	for i := 0; i < 3; i++ {
		if dist[i][i] != 0 {
			t.Errorf("d(%d,%d) = %f, want 0", i, i, dist[i][i])
		}
	}
}

func TestEuclideanDistance(t *testing.T) {
	tests := []struct {
		a, b []float64
		want float64
	}{
		{[]float64{0, 0}, []float64{3, 4}, 5.0},
		{[]float64{1, 1, 1}, []float64{1, 1, 1}, 0.0},
		{[]float64{0}, []float64{5}, 5.0},
		{[]float64{1, 2, 3}, []float64{4, 6, 3}, 5.0}, // sqrt(9+16+0)
	}
	for _, tc := range tests {
		got := EuclideanDistance(tc.a, tc.b)
		if !almostEqual(got, tc.want, 1e-9) {
			t.Errorf("EuclideanDistance(%v, %v) = %f, want %f", tc.a, tc.b, got, tc.want)
		}
	}

	// Mismatched dimensions should return Inf
	got := EuclideanDistance([]float64{1, 2}, []float64{1, 2, 3})
	if !math.IsInf(got, 1) {
		t.Errorf("mismatched dimensions should return +Inf, got %f", got)
	}
}

// ---------- persistence.go tests ----------

// makeClusteredFindings creates findings that form distinct clusters based on
// their category and threat level. cluster0 and cluster1 are well-separated.
func makeClusteredFindings(sizes ...int) []models.Finding {
	var findings []models.Finding
	idx := 0
	categories := []models.AlgorithmCategory{
		models.CategoryAsymmetricEncryption,
		models.CategorySymmetricEncryption,
		models.CategoryHashing,
	}
	threats := []models.QuantumThreatLevel{
		models.ThreatBrokenByShor,
		models.ThreatWeakenedByGrover,
		models.ThreatNotDirectlyThreatened,
	}
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityMedium,
		models.SeverityLow,
	}

	for clusterIdx, size := range sizes {
		ci := clusterIdx % len(categories)
		for j := 0; j < size; j++ {
			findings = append(findings, models.Finding{
				ID:            fmt.Sprintf("C%d-F%d", clusterIdx, j),
				Severity:      severities[ci],
				QuantumThreat: threats[ci],
				Category:      categories[ci],
				Algorithm:     fmt.Sprintf("ALG-%d", ci),
				FilePath:      fmt.Sprintf("/src/cluster%d/file%d.go", clusterIdx, j),
				Confidence:    0.9,
			})
			idx++
		}
	}
	return findings
}

func TestPersistence_TwoClusters(t *testing.T) {
	// Two tight groups with very different characteristics
	findings := makeClusteredFindings(5, 5)

	pa := NewPersistenceAnalyzer(WithPersistenceThreshold(0.3))
	result, err := pa.ComputePersistence(findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// There should be persistence pairs
	if len(result.Pairs) == 0 {
		t.Fatal("expected persistence pairs, got none")
	}

	// The most persistent pair should have significant persistence
	topPersistence := result.Pairs[0].Persistence
	if topPersistence <= 0 {
		t.Errorf("top persistence should be > 0, got %f", topPersistence)
	}

	// Should have at least 1 stable cluster
	if len(result.StableClusters) < 1 {
		t.Errorf("expected at least 1 stable cluster, got %d", len(result.StableClusters))
	}

	// Total findings across all clusters should equal input
	totalInClusters := 0
	for _, c := range result.StableClusters {
		totalInClusters += len(c.FindingIDs)
	}
	if totalInClusters != len(findings) {
		t.Errorf("total findings in clusters = %d, want %d", totalInClusters, len(findings))
	}
}

func TestPersistence_ThreeClusters(t *testing.T) {
	findings := makeClusteredFindings(4, 4, 4)

	pa := NewPersistenceAnalyzer(WithPersistenceThreshold(0.25))
	result, err := pa.ComputePersistence(findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With three distinct groups we expect at least 2 persistent pairs
	// (N-1 merges total, at least 2 should be significant inter-cluster merges)
	highPersistenceCount := 0
	if len(result.Pairs) > 0 {
		// Count pairs with persistence > 50% of the max
		maxP := result.Pairs[0].Persistence
		for _, p := range result.Pairs {
			if p.Persistence > maxP*0.5 {
				highPersistenceCount++
			}
		}
	}
	if highPersistenceCount < 2 {
		t.Errorf("expected at least 2 high-persistence pairs for 3 clusters, got %d", highPersistenceCount)
	}

	// Should have clusters
	if len(result.StableClusters) < 2 {
		t.Errorf("expected at least 2 stable clusters for 3 groups, got %d", len(result.StableClusters))
	}

	// Each cluster should have a description
	for i, c := range result.StableClusters {
		if c.Description == "" {
			t.Errorf("cluster %d has empty description", i)
		}
	}
}

func TestPersistenceEntropy_SingleCluster(t *testing.T) {
	// All pairs with equal persistence -> maximum entropy
	// Single pair -> zero entropy
	singlePair := []PersistencePair{
		{Birth: 0, Death: 1, Persistence: 1.0},
	}
	h := PersistenceEntropy(singlePair)
	// With a single pair, ratio = 1.0, log(1.0) = 0, so entropy = 0
	if !almostEqual(h, 0, 1e-9) {
		t.Errorf("entropy of single pair should be 0, got %f", h)
	}

	// Two equal pairs -> entropy = log(2)
	twoPairs := []PersistencePair{
		{Birth: 0, Death: 1, Persistence: 1.0},
		{Birth: 0, Death: 1, Persistence: 1.0},
	}
	h2 := PersistenceEntropy(twoPairs)
	if !almostEqual(h2, math.Log(2), 1e-9) {
		t.Errorf("entropy of two equal pairs should be ln(2)=%f, got %f", math.Log(2), h2)
	}

	// Empty pairs -> 0
	h0 := PersistenceEntropy(nil)
	if h0 != 0 {
		t.Errorf("entropy of empty pairs should be 0, got %f", h0)
	}

	// One dominant pair + many small pairs -> low entropy
	mixedPairs := []PersistencePair{
		{Persistence: 10.0},
		{Persistence: 0.01},
		{Persistence: 0.01},
		{Persistence: 0.01},
	}
	hMixed := PersistenceEntropy(mixedPairs)
	hUniform := PersistenceEntropy([]PersistencePair{
		{Persistence: 1.0},
		{Persistence: 1.0},
		{Persistence: 1.0},
		{Persistence: 1.0},
	})
	if hMixed >= hUniform {
		t.Errorf("mixed entropy (%f) should be less than uniform entropy (%f)", hMixed, hUniform)
	}
}

func TestEmbedFindings(t *testing.T) {
	findings := []models.Finding{
		{
			ID:              "F-1",
			Severity:        models.SeverityCritical,
			QuantumThreat:   models.ThreatBrokenByShor,
			Category:        models.CategoryAsymmetricEncryption,
			DataSensitivity: "PII",
			InDependency:    true,
			DependencyChain: []string{"dep1", "dep2"},
			Confidence:      0.95,
			FilePath:        "/src/crypto.go",
		},
		{
			ID:            "F-2",
			Severity:      models.SeverityLow,
			QuantumThreat: models.ThreatNotDirectlyThreatened,
			Category:      models.CategoryHashing,
			Confidence:    0.5,
			FilePath:      "/src/hash.go",
		},
	}

	vectors := EmbedFindings(findings)

	if len(vectors) != 2 {
		t.Fatalf("expected 2 vectors, got %d", len(vectors))
	}

	expectedDim := FeatureDimension()
	for i, v := range vectors {
		if len(v) != expectedDim {
			t.Errorf("vector[%d] has %d dimensions, want %d", i, len(v), expectedDim)
		}
	}

	// F-1: Critical severity -> v[0] should be 1.0
	if !almostEqual(vectors[0][0], 1.0, 1e-9) {
		t.Errorf("F-1 severity normalized = %f, want 1.0", vectors[0][0])
	}

	// F-1: Shor threat -> v[1] should be 1.0
	if !almostEqual(vectors[0][1], 1.0, 1e-9) {
		t.Errorf("F-1 quantum threat normalized = %f, want 1.0", vectors[0][1])
	}

	// F-1: has data sensitivity -> v[2] should be 1.0
	if !almostEqual(vectors[0][2], 1.0, 1e-9) {
		t.Errorf("F-1 data sensitivity = %f, want 1.0", vectors[0][2])
	}

	// F-1: in dependency -> v[3] should be 1.0
	if !almostEqual(vectors[0][3], 1.0, 1e-9) {
		t.Errorf("F-1 in_dependency = %f, want 1.0", vectors[0][3])
	}

	// F-1: dep chain length 2, normalized to 0.2
	if !almostEqual(vectors[0][4], 0.2, 1e-9) {
		t.Errorf("F-1 dep_depth = %f, want 0.2", vectors[0][4])
	}

	// F-1: confidence 0.95
	if !almostEqual(vectors[0][5], 0.95, 1e-9) {
		t.Errorf("F-1 confidence = %f, want 0.95", vectors[0][5])
	}

	// F-1: AsymmetricEncryption is category 0, so v[7] should be 1.0
	if !almostEqual(vectors[0][7], 1.0, 1e-9) {
		t.Errorf("F-1 asymmetric encryption one-hot = %f, want 1.0", vectors[0][7])
	}

	// F-2: Low severity -> v[0] should be 0.0
	if !almostEqual(vectors[1][0], 0.0, 1e-9) {
		t.Errorf("F-2 severity normalized = %f, want 0.0", vectors[1][0])
	}

	// F-2: NotThreatened -> v[1] should be 0.0
	if !almostEqual(vectors[1][1], 0.0, 1e-9) {
		t.Errorf("F-2 quantum threat normalized = %f, want 0.0", vectors[1][1])
	}

	// F-2: no data sensitivity -> v[2] should be 0.0
	if !almostEqual(vectors[1][2], 0.0, 1e-9) {
		t.Errorf("F-2 data sensitivity = %f, want 0.0", vectors[1][2])
	}

	// F-2: Hashing is category 4, so v[7+4]=v[11] should be 1.0
	if !almostEqual(vectors[1][11], 1.0, 1e-9) {
		t.Errorf("F-2 hashing one-hot = %f, want 1.0", vectors[1][11])
	}

	// The two vectors should be different
	dist := EuclideanDistance(vectors[0], vectors[1])
	if dist < 0.5 {
		t.Errorf("distance between very different findings should be > 0.5, got %f", dist)
	}
}
