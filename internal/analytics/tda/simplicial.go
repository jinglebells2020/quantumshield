package tda

import "math"

// SimplicialComplex represents a filtered simplicial complex built from
// pairwise distances between points.
type SimplicialComplex struct {
	Vertices  []int      `json:"vertices"`
	Edges     [][2]int   `json:"edges"`
	EdgeDists []float64  `json:"edge_dists"`
}

// UnionFind implements a disjoint-set data structure with union-by-rank,
// path compression, and birth tracking for persistence computation.
type UnionFind struct {
	parent []int
	rank   []int
	size   []int
	birth  []float64
}

// NewUnionFind creates a UnionFind for n elements, each in its own set.
// All components are born at distance 0.
func NewUnionFind(n int) *UnionFind {
	uf := &UnionFind{
		parent: make([]int, n),
		rank:   make([]int, n),
		size:   make([]int, n),
		birth:  make([]float64, n),
	}
	for i := 0; i < n; i++ {
		uf.parent[i] = i
		uf.size[i] = 1
		uf.birth[i] = 0
	}
	return uf
}

// Find returns the representative of the set containing x, with path
// compression.
func (uf *UnionFind) Find(x int) int {
	for uf.parent[x] != x {
		uf.parent[x] = uf.parent[uf.parent[x]] // path halving
		x = uf.parent[x]
	}
	return x
}

// Union merges the sets containing x and y. It uses the elder rule: the
// component with the smaller (earlier) birth value becomes the root. If births
// are equal, the component with higher rank wins. Returns the merged root,
// the absorbed root, and whether a merge actually happened.
func (uf *UnionFind) Union(x, y int) (mergedRoot, absorbedRoot int, absorbed bool) {
	rx, ry := uf.Find(x), uf.Find(y)
	if rx == ry {
		return rx, ry, false
	}

	// Elder rule: the component born earlier (lower birth) survives.
	// If births are equal, fall back to union-by-rank.
	if uf.birth[rx] > uf.birth[ry] {
		rx, ry = ry, rx // ensure rx is the elder
	} else if uf.birth[rx] == uf.birth[ry] && uf.rank[rx] < uf.rank[ry] {
		rx, ry = ry, rx
	}

	// rx becomes root, ry is absorbed
	uf.parent[ry] = rx
	uf.size[rx] += uf.size[ry]
	if uf.rank[rx] == uf.rank[ry] {
		uf.rank[rx]++
	}

	return rx, ry, true
}

// Size returns the number of elements in the set containing x.
func (uf *UnionFind) Size(x int) int {
	return uf.size[uf.Find(x)]
}

// Birth returns the birth time of the component containing x.
func (uf *UnionFind) Birth(x int) float64 {
	return uf.birth[uf.Find(x)]
}

// PairwiseDistances computes the full pairwise Euclidean distance matrix for
// a set of points, where each point is a float64 slice of the same dimension.
func PairwiseDistances(points [][]float64) [][]float64 {
	n := len(points)
	dist := make([][]float64, n)
	for i := 0; i < n; i++ {
		dist[i] = make([]float64, n)
		for j := 0; j < n; j++ {
			if i != j {
				dist[i][j] = EuclideanDistance(points[i], points[j])
			}
		}
	}
	return dist
}

// EuclideanDistance computes the L2 distance between two vectors of the same
// dimension.
func EuclideanDistance(a, b []float64) float64 {
	if len(a) != len(b) {
		return math.Inf(1)
	}
	sum := 0.0
	for i := range a {
		d := a[i] - b[i]
		sum += d * d
	}
	return math.Sqrt(sum)
}
