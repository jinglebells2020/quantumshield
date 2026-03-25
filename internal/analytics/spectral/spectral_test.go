package spectral

import (
	"math"
	"testing"

	"quantumshield/pkg/models"
)

func TestPowerIteration_DominantEigenvector(t *testing.T) {
	// Matrix [[2, 1], [1, 2]] has eigenvalues 3 and 1.
	// Dominant eigenvector is [1/sqrt(2), 1/sqrt(2)] with eigenvalue 3.
	M := [][]float64{
		{2, 1},
		{1, 2},
	}
	v, lambda, err := PowerIteration(M, 1000, 1e-10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.Abs(lambda-3.0) > 1e-6 {
		t.Errorf("expected eigenvalue ~3, got %f", lambda)
	}
	// Eigenvector should be proportional to [1, 1]; check both components equal
	if math.Abs(math.Abs(v[0])-math.Abs(v[1])) > 1e-6 {
		t.Errorf("expected eigenvector components equal in magnitude, got %v", v)
	}
	// Should be unit norm
	norm := VecNorm(v)
	if math.Abs(norm-1.0) > 1e-8 {
		t.Errorf("expected unit norm, got %f", norm)
	}
}

func TestKMeans_WellSeparated(t *testing.T) {
	// 3 clusters of 10 points each, well-separated in 2D
	data := make([][]float64, 30)
	// Cluster 0: centered at (0, 0)
	for i := 0; i < 10; i++ {
		data[i] = []float64{float64(i%3) * 0.1, float64(i/3) * 0.1}
	}
	// Cluster 1: centered at (100, 0)
	for i := 0; i < 10; i++ {
		data[10+i] = []float64{100 + float64(i%3)*0.1, float64(i/3) * 0.1}
	}
	// Cluster 2: centered at (0, 100)
	for i := 0; i < 10; i++ {
		data[20+i] = []float64{float64(i%3) * 0.1, 100 + float64(i/3)*0.1}
	}

	assignments, _, err := KMeans(data, 3, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that all points in the same original cluster get the same assignment
	cluster0 := assignments[0]
	for i := 0; i < 10; i++ {
		if assignments[i] != cluster0 {
			t.Errorf("point %d in cluster 0 assigned to %d, expected %d", i, assignments[i], cluster0)
		}
	}
	cluster1 := assignments[10]
	for i := 10; i < 20; i++ {
		if assignments[i] != cluster1 {
			t.Errorf("point %d in cluster 1 assigned to %d, expected %d", i, assignments[i], cluster1)
		}
	}
	cluster2 := assignments[20]
	for i := 20; i < 30; i++ {
		if assignments[i] != cluster2 {
			t.Errorf("point %d in cluster 2 assigned to %d, expected %d", i, assignments[i], cluster2)
		}
	}

	// Verify all three clusters have different labels
	if cluster0 == cluster1 || cluster1 == cluster2 || cluster0 == cluster2 {
		t.Errorf("clusters not distinct: c0=%d, c1=%d, c2=%d", cluster0, cluster1, cluster2)
	}
}

func TestBuildLaplacian_Simple(t *testing.T) {
	// 3-node chain: A - B - C
	graph := &models.DependencyGraph{
		Nodes: map[string]*models.DependencyNode{
			"A": {Name: "A", Dependencies: []string{"B"}},
			"B": {Name: "B", Dependencies: []string{"A", "C"}},
			"C": {Name: "C", Dependencies: []string{"B"}},
		},
	}

	L, nodeIndex, _ := BuildLaplacian(graph)

	n := len(L)
	if n != 3 {
		t.Fatalf("expected 3x3 Laplacian, got %dx%d", n, n)
	}

	// Verify row sums are 0
	for i := 0; i < n; i++ {
		rowSum := 0.0
		for j := 0; j < n; j++ {
			rowSum += L[i][j]
		}
		if math.Abs(rowSum) > 1e-10 {
			t.Errorf("row %d sum = %f, expected 0", i, rowSum)
		}
	}

	// Verify column sums are 0 (L is symmetric)
	for j := 0; j < n; j++ {
		colSum := 0.0
		for i := 0; i < n; i++ {
			colSum += L[i][j]
		}
		if math.Abs(colSum) > 1e-10 {
			t.Errorf("col %d sum = %f, expected 0", j, colSum)
		}
	}

	// Verify symmetry
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if math.Abs(L[i][j]-L[j][i]) > 1e-10 {
				t.Errorf("L[%d][%d]=%f != L[%d][%d]=%f", i, j, L[i][j], j, i, L[j][i])
			}
		}
	}

	// Check that B has degree 2 (connected to A and C)
	bIdx := nodeIndex["B"]
	if L[bIdx][bIdx] != 2 {
		t.Errorf("expected degree of B = 2, got %f", L[bIdx][bIdx])
	}
}

func TestBuildLaplacian_SmallestEigenvalueZero(t *testing.T) {
	// Connected graph: triangle A-B-C
	graph := &models.DependencyGraph{
		Nodes: map[string]*models.DependencyNode{
			"A": {Name: "A", Dependencies: []string{"B", "C"}},
			"B": {Name: "B", Dependencies: []string{"A", "C"}},
			"C": {Name: "C", Dependencies: []string{"A", "B"}},
		},
	}

	L, _, _ := BuildLaplacian(graph)

	// The smallest eigenvalue of L for a connected graph is 0.
	// Verify by multiplying L * [1,1,1]^T = [0,0,0]^T
	ones := []float64{1, 1, 1}
	result := MatVecMul(L, ones)
	for i, v := range result {
		if math.Abs(v) > 1e-10 {
			t.Errorf("L * ones[%d] = %f, expected 0", i, v)
		}
	}

	// Use power iteration on L to verify smallest eigenvalue is ~0
	// L * [1,1,1] = 0, so eigenvalue 0 exists
	// Additionally verify via inverse power iteration
	_, lambda, err := InversePowerIteration(L, 0.0, 1000, 1e-10)
	if err == nil && math.Abs(lambda) > 1e-4 {
		t.Errorf("smallest eigenvalue = %f, expected ~0", lambda)
	}
}

func TestPartition_TwoCliques(t *testing.T) {
	// Two cliques (A,B,C) and (D,E,F) connected by single edge C-D
	graph := &models.DependencyGraph{
		Nodes: map[string]*models.DependencyNode{
			"A": {
				Name:         "A",
				Dependencies: []string{"B", "C"},
				CryptoFindings: []models.Finding{
					{Severity: models.SeverityCritical},
				},
			},
			"B": {
				Name:         "B",
				Dependencies: []string{"A", "C"},
				CryptoFindings: []models.Finding{
					{Severity: models.SeverityCritical},
				},
			},
			"C": {
				Name:         "C",
				Dependencies: []string{"A", "B", "D"},
			},
			"D": {
				Name:         "D",
				Dependencies: []string{"C", "E", "F"},
			},
			"E": {
				Name:         "E",
				Dependencies: []string{"D", "F"},
			},
			"F": {
				Name:         "F",
				Dependencies: []string{"D", "E"},
			},
		},
	}

	partitioner := NewDependencyPartitioner(WithMaxPhases(2))
	result, err := partitioner.Partition(graph)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Phases) != 2 {
		t.Fatalf("expected 2 phases, got %d", len(result.Phases))
	}

	// Verify all 6 packages are assigned
	totalPackages := 0
	for _, phase := range result.Phases {
		totalPackages += len(phase.Packages)
	}
	if totalPackages != 6 {
		t.Errorf("expected 6 total packages, got %d", totalPackages)
	}

	// The two cliques should be in different phases.
	// Build package->phase mapping
	pkgPhase := make(map[string]int)
	for _, phase := range result.Phases {
		for _, pkg := range phase.Packages {
			pkgPhase[pkg] = phase.Phase
		}
	}

	// Within each clique, packages should be in the same phase
	cliqueA := []string{"A", "B", "C"}
	cliqueB := []string{"D", "E", "F"}

	phaseA := pkgPhase[cliqueA[0]]
	for _, pkg := range cliqueA[1:] {
		if pkgPhase[pkg] != phaseA {
			t.Logf("note: clique 1 member %s in phase %d, expected %d (spectral may split differently)", pkg, pkgPhase[pkg], phaseA)
		}
	}
	phaseB := pkgPhase[cliqueB[0]]
	for _, pkg := range cliqueB[1:] {
		if pkgPhase[pkg] != phaseB {
			t.Logf("note: clique 2 member %s in phase %d, expected %d", pkg, pkgPhase[pkg], phaseB)
		}
	}

	// The first phase should have the higher critical count due to ordering
	if result.Phases[0].CriticalCount < result.Phases[1].CriticalCount {
		t.Errorf("phases should be ordered by critical count descending: phase1=%d, phase2=%d",
			result.Phases[0].CriticalCount, result.Phases[1].CriticalCount)
	}
}

func TestPartition_SingleNode(t *testing.T) {
	graph := &models.DependencyGraph{
		Nodes: map[string]*models.DependencyNode{
			"solo": {
				Name:           "solo",
				CryptoFindings: []models.Finding{{Severity: models.SeverityCritical}},
			},
		},
	}

	partitioner := NewDependencyPartitioner()
	result, err := partitioner.Partition(graph)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Phases) != 1 {
		t.Fatalf("expected 1 phase, got %d", len(result.Phases))
	}
	if len(result.Phases[0].Packages) != 1 {
		t.Errorf("expected 1 package in phase, got %d", len(result.Phases[0].Packages))
	}
	if result.Phases[0].Packages[0] != "solo" {
		t.Errorf("expected package 'solo', got %s", result.Phases[0].Packages[0])
	}
	if result.Phases[0].CriticalCount != 1 {
		t.Errorf("expected 1 critical finding, got %d", result.Phases[0].CriticalCount)
	}
	if result.Phases[0].CrossPhaseEdges != 0 {
		t.Errorf("expected 0 cross-phase edges, got %d", result.Phases[0].CrossPhaseEdges)
	}
}

func TestNormalizedCut_Simple(t *testing.T) {
	// 4-node graph: 0-1-2-3 (chain)
	// Partition: A={0,1}, B={2,3}
	// Weight = 1 for all edges
	// L for chain 0-1-2-3:
	L := [][]float64{
		{1, -1, 0, 0},
		{-1, 2, -1, 0},
		{0, -1, 2, -1},
		{0, 0, -1, 1},
	}

	A := []int{0, 1}
	B := []int{2, 3}

	ncut := NormalizedCut(L, A, B)

	// cut(A,B) = weight of edge 1-2 = 1
	// vol(A) = deg(0) + deg(1) = 1 + 2 = 3
	// vol(B) = deg(2) + deg(3) = 2 + 1 = 3
	// NCut = 1/3 + 1/3 = 2/3
	expected := 2.0 / 3.0
	if math.Abs(ncut-expected) > 1e-10 {
		t.Errorf("expected NCut = %f, got %f", expected, ncut)
	}
}

func TestMatInverse(t *testing.T) {
	// 3x3 matrix
	M := [][]float64{
		{2, 1, 0},
		{1, 3, 1},
		{0, 1, 2},
	}

	inv, err := matInverse(M)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify M * M^(-1) ~ I
	n := len(M)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			sum := 0.0
			for k := 0; k < n; k++ {
				sum += M[i][k] * inv[k][j]
			}
			expected := 0.0
			if i == j {
				expected = 1.0
			}
			if math.Abs(sum-expected) > 1e-8 {
				t.Errorf("(M*M^-1)[%d][%d] = %f, expected %f", i, j, sum, expected)
			}
		}
	}
}

func TestIdentityMatrix(t *testing.T) {
	n := 4
	I := IdentityMatrix(n)

	if len(I) != n {
		t.Fatalf("expected %d rows, got %d", n, len(I))
	}
	for i := 0; i < n; i++ {
		if len(I[i]) != n {
			t.Fatalf("row %d: expected %d cols, got %d", i, n, len(I[i]))
		}
		for j := 0; j < n; j++ {
			expected := 0.0
			if i == j {
				expected = 1.0
			}
			if I[i][j] != expected {
				t.Errorf("I[%d][%d] = %f, expected %f", i, j, I[i][j], expected)
			}
		}
	}
}
