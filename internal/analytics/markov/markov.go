// Package markov provides shared Markov chain matrix operations and analytics
// modules for quantum migration prediction, developer behavior modeling,
// and HNDL (Harvest Now, Decrypt Later) attack lifecycle analysis.
package markov

import (
	"errors"
	"math"
)

// NumStates is the fixed dimension for the standard Markov chain matrices
// used across modules (migration states, HNDL states, etc.).
const NumStates = 5

// MatrixMultiply performs standard NxN matrix multiplication C = A * B
// for fixed-size NumStates x NumStates matrices.
func MatrixMultiply(A, B [NumStates][NumStates]float64) [NumStates][NumStates]float64 {
	var C [NumStates][NumStates]float64
	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			sum := 0.0
			for k := 0; k < NumStates; k++ {
				sum += A[i][k] * B[k][j]
			}
			C[i][j] = sum
		}
	}
	return C
}

// MatrixPower computes P^n using repeated squaring in O(log n) matrix multiplications.
// For n <= 0, returns the identity matrix.
func MatrixPower(P [NumStates][NumStates]float64, n int) [NumStates][NumStates]float64 {
	// Start with identity matrix
	var result [NumStates][NumStates]float64
	for i := 0; i < NumStates; i++ {
		result[i][i] = 1.0
	}

	if n <= 0 {
		return result
	}

	base := P
	exp := n
	for exp > 0 {
		if exp%2 == 1 {
			result = MatrixMultiply(result, base)
		}
		base = MatrixMultiply(base, base)
		exp /= 2
	}
	return result
}

// MatrixInverse computes the inverse of an arbitrary-sized square matrix using
// Gaussian elimination with partial pivoting. Returns an error if the matrix
// is singular (or near-singular).
func MatrixInverse(M [][]float64) ([][]float64, error) {
	n := len(M)
	if n == 0 {
		return nil, errors.New("markov: cannot invert empty matrix")
	}
	for _, row := range M {
		if len(row) != n {
			return nil, errors.New("markov: matrix must be square")
		}
	}

	// Build augmented matrix [M | I]
	aug := make([][]float64, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]float64, 2*n)
		for j := 0; j < n; j++ {
			aug[i][j] = M[i][j]
		}
		aug[i][n+i] = 1.0
	}

	const eps = 1e-12

	// Forward elimination with partial pivoting
	for col := 0; col < n; col++ {
		// Find pivot row
		maxVal := math.Abs(aug[col][col])
		maxRow := col
		for row := col + 1; row < n; row++ {
			if v := math.Abs(aug[row][col]); v > maxVal {
				maxVal = v
				maxRow = row
			}
		}

		if maxVal < eps {
			return nil, errors.New("markov: matrix is singular or near-singular")
		}

		// Swap rows
		if maxRow != col {
			aug[col], aug[maxRow] = aug[maxRow], aug[col]
		}

		// Scale pivot row
		pivot := aug[col][col]
		for j := 0; j < 2*n; j++ {
			aug[col][j] /= pivot
		}

		// Eliminate column in all other rows
		for row := 0; row < n; row++ {
			if row == col {
				continue
			}
			factor := aug[row][col]
			for j := 0; j < 2*n; j++ {
				aug[row][j] -= factor * aug[col][j]
			}
		}
	}

	// Extract inverse from augmented matrix
	inv := make([][]float64, n)
	for i := 0; i < n; i++ {
		inv[i] = make([]float64, n)
		for j := 0; j < n; j++ {
			inv[i][j] = aug[i][n+j]
		}
	}

	return inv, nil
}

// VectorMatrixMultiply computes v * M where v is a row vector and M is
// a NumStates x NumStates matrix. Returns the resulting row vector.
func VectorMatrixMultiply(v [NumStates]float64, M [NumStates][NumStates]float64) [NumStates]float64 {
	var result [NumStates]float64
	for j := 0; j < NumStates; j++ {
		sum := 0.0
		for i := 0; i < NumStates; i++ {
			sum += v[i] * M[i][j]
		}
		result[j] = sum
	}
	return result
}

// VectorDiffNorm computes the L-infinity norm (max absolute difference) of a - b.
func VectorDiffNorm(a, b [NumStates]float64) float64 {
	maxDiff := 0.0
	for i := 0; i < NumStates; i++ {
		d := math.Abs(a[i] - b[i])
		if d > maxDiff {
			maxDiff = d
		}
	}
	return maxDiff
}
