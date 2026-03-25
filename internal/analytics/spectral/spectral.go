package spectral

import (
	"errors"
	"math"
	"math/rand"
)

// PowerIteration finds the dominant eigenvector of M.
// Iterates v = M·v / ||M·v|| until convergence.
func PowerIteration(M [][]float64, maxIter int, tol float64) (eigenvector []float64, eigenvalue float64, err error) {
	n := len(M)
	if n == 0 {
		return nil, 0, errors.New("empty matrix")
	}
	v := make([]float64, n)
	rng := rand.New(rand.NewSource(42))
	for i := range v {
		v[i] = rng.NormFloat64()
	}
	norm := VecNorm(v)
	for i := range v {
		v[i] /= norm
	}

	for iter := 0; iter < maxIter; iter++ {
		w := MatVecMul(M, v)
		norm = VecNorm(w)
		if norm == 0 {
			return nil, 0, errors.New("zero vector during iteration")
		}
		newV := make([]float64, n)
		for i := range w {
			newV[i] = w[i] / norm
		}
		diff := 0.0
		for i := range v {
			d := math.Abs(newV[i] - v[i])
			if d > diff {
				diff = d
			}
		}
		v = newV
		eigenvalue = norm
		if diff < tol {
			break
		}
	}
	return v, eigenvalue, nil
}

// InversePowerIteration finds the eigenvector for the eigenvalue closest to shift.
func InversePowerIteration(M [][]float64, shift float64, maxIter int, tol float64) (eigenvector []float64, eigenvalue float64, err error) {
	n := len(M)
	shifted := make([][]float64, n)
	for i := range M {
		shifted[i] = make([]float64, n)
		copy(shifted[i], M[i])
		shifted[i][i] -= shift
	}
	inv, err := matInverse(shifted)
	if err != nil {
		return nil, 0, err
	}
	v, mu, err := PowerIteration(inv, maxIter, tol)
	if err != nil {
		return nil, 0, err
	}
	if mu == 0 {
		return v, shift, nil
	}
	return v, shift + 1.0/mu, nil
}

// matInverse computes matrix inverse via Gaussian elimination with partial pivoting.
func matInverse(M [][]float64) ([][]float64, error) {
	n := len(M)
	aug := make([][]float64, n)
	for i := range M {
		aug[i] = make([]float64, 2*n)
		copy(aug[i], M[i])
		aug[i][n+i] = 1
	}
	for col := 0; col < n; col++ {
		maxRow := col
		maxVal := math.Abs(aug[col][col])
		for row := col + 1; row < n; row++ {
			if math.Abs(aug[row][col]) > maxVal {
				maxVal = math.Abs(aug[row][col])
				maxRow = row
			}
		}
		if maxVal < 1e-14 {
			return nil, errors.New("singular matrix")
		}
		aug[col], aug[maxRow] = aug[maxRow], aug[col]
		pivot := aug[col][col]
		for j := range aug[col] {
			aug[col][j] /= pivot
		}
		for row := 0; row < n; row++ {
			if row == col {
				continue
			}
			factor := aug[row][col]
			for j := range aug[row] {
				aug[row][j] -= factor * aug[col][j]
			}
		}
	}
	result := make([][]float64, n)
	for i := range result {
		result[i] = make([]float64, n)
		copy(result[i], aug[i][n:])
	}
	return result, nil
}

// KMeans performs k-means clustering with k-means++ initialization.
func KMeans(data [][]float64, k int, maxIter int) (assignments []int, centroids [][]float64, err error) {
	n := len(data)
	if n == 0 || k <= 0 {
		return nil, nil, errors.New("invalid input")
	}
	if k >= n {
		assignments = make([]int, n)
		for i := range assignments {
			assignments[i] = i
		}
		return assignments, data, nil
	}
	dim := len(data[0])
	rng := rand.New(rand.NewSource(42))

	// k-means++ init
	centroids = make([][]float64, k)
	first := rng.Intn(n)
	centroids[0] = make([]float64, dim)
	copy(centroids[0], data[first])

	for c := 1; c < k; c++ {
		dists := make([]float64, n)
		total := 0.0
		for i := range data {
			minD := math.Inf(1)
			for j := 0; j < c; j++ {
				d := eucDist(data[i], centroids[j])
				if d < minD {
					minD = d
				}
			}
			dists[i] = minD * minD
			total += dists[i]
		}
		r := rng.Float64() * total
		cumul := 0.0
		chosen := 0
		for i, d := range dists {
			cumul += d
			if cumul >= r {
				chosen = i
				break
			}
		}
		centroids[c] = make([]float64, dim)
		copy(centroids[c], data[chosen])
	}

	assignments = make([]int, n)
	for iter := 0; iter < maxIter; iter++ {
		changed := false
		for i := range data {
			best := 0
			bestD := math.Inf(1)
			for j := range centroids {
				d := eucDist(data[i], centroids[j])
				if d < bestD {
					bestD = d
					best = j
				}
			}
			if assignments[i] != best {
				assignments[i] = best
				changed = true
			}
		}
		if !changed {
			break
		}
		// Update centroids
		for j := range centroids {
			for d := range centroids[j] {
				centroids[j][d] = 0
			}
		}
		counts := make([]int, k)
		for i, a := range assignments {
			counts[a]++
			for d := range data[i] {
				centroids[a][d] += data[i][d]
			}
		}
		for j := range centroids {
			if counts[j] > 0 {
				for d := range centroids[j] {
					centroids[j][d] /= float64(counts[j])
				}
			}
		}
	}
	return assignments, centroids, nil
}

func eucDist(a, b []float64) float64 {
	var sum float64
	for i := range a {
		d := a[i] - b[i]
		sum += d * d
	}
	return math.Sqrt(sum)
}

// MatVecMul multiplies matrix M by vector v.
func MatVecMul(M [][]float64, v []float64) []float64 {
	n := len(M)
	result := make([]float64, n)
	for i := range M {
		for j := range v {
			result[i] += M[i][j] * v[j]
		}
	}
	return result
}

// VecNorm computes L2 norm.
func VecNorm(v []float64) float64 {
	var sum float64
	for _, x := range v {
		sum += x * x
	}
	return math.Sqrt(sum)
}

// VecDot computes dot product.
func VecDot(a, b []float64) float64 {
	var sum float64
	for i := range a {
		sum += a[i] * b[i]
	}
	return sum
}

// IdentityMatrix creates an n*n identity matrix.
func IdentityMatrix(n int) [][]float64 {
	m := make([][]float64, n)
	for i := range m {
		m[i] = make([]float64, n)
		m[i][i] = 1
	}
	return m
}
