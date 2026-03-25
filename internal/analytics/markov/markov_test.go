package markov

import (
	"math"
	"testing"
)

const testTol = 1e-9

func TestMatrixMultiply_Identity(t *testing.T) {
	// Multiplying any matrix by the identity should return the same matrix
	var identity [NumStates][NumStates]float64
	for i := 0; i < NumStates; i++ {
		identity[i][i] = 1.0
	}

	var M [NumStates][NumStates]float64
	M[0][0] = 0.5
	M[0][1] = 0.3
	M[0][2] = 0.2
	M[1][0] = 0.1
	M[1][1] = 0.6
	M[1][2] = 0.3
	M[2][0] = 0.0
	M[2][1] = 0.2
	M[2][2] = 0.8
	M[3][3] = 1.0
	M[4][4] = 1.0

	// M * I should equal M
	result := MatrixMultiply(M, identity)
	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			if math.Abs(result[i][j]-M[i][j]) > testTol {
				t.Errorf("M*I [%d][%d]: got %f, want %f", i, j, result[i][j], M[i][j])
			}
		}
	}

	// I * M should equal M
	result2 := MatrixMultiply(identity, M)
	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			if math.Abs(result2[i][j]-M[i][j]) > testTol {
				t.Errorf("I*M [%d][%d]: got %f, want %f", i, j, result2[i][j], M[i][j])
			}
		}
	}
}

func TestMatrixPower_Squared(t *testing.T) {
	// P^2 should match manual P*P
	var P [NumStates][NumStates]float64
	P[0][0] = 0.5
	P[0][1] = 0.5
	P[1][0] = 0.3
	P[1][1] = 0.4
	P[1][2] = 0.3
	P[2][1] = 0.2
	P[2][2] = 0.6
	P[2][3] = 0.2
	P[3][2] = 0.1
	P[3][3] = 0.7
	P[3][4] = 0.2
	P[4][4] = 1.0

	// Compute P^2 via MatrixPower
	P2power := MatrixPower(P, 2)

	// Compute P*P manually
	P2manual := MatrixMultiply(P, P)

	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			if math.Abs(P2power[i][j]-P2manual[i][j]) > testTol {
				t.Errorf("P^2 [%d][%d]: MatrixPower=%f, MatrixMultiply=%f",
					i, j, P2power[i][j], P2manual[i][j])
			}
		}
	}

	// Also verify P^0 is identity
	P0 := MatrixPower(P, 0)
	for i := 0; i < NumStates; i++ {
		for j := 0; j < NumStates; j++ {
			expected := 0.0
			if i == j {
				expected = 1.0
			}
			if math.Abs(P0[i][j]-expected) > testTol {
				t.Errorf("P^0 [%d][%d]: got %f, want %f", i, j, P0[i][j], expected)
			}
		}
	}
}

func TestMatrixInverse_Simple(t *testing.T) {
	// A simple 3x3 matrix
	M := [][]float64{
		{2, 1, 1},
		{1, 3, 2},
		{1, 0, 0},
	}

	inv, err := MatrixInverse(M)
	if err != nil {
		t.Fatalf("MatrixInverse returned error: %v", err)
	}

	// Verify M * M^(-1) = I
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
				t.Errorf("M*M^(-1) [%d][%d]: got %f, want %f", i, j, sum, expected)
			}
		}
	}
}

func TestMatrixInverse_Singular(t *testing.T) {
	// Singular matrix: row 2 = row 1
	M := [][]float64{
		{1, 2, 3},
		{4, 5, 6},
		{4, 5, 6},
	}

	_, err := MatrixInverse(M)
	if err == nil {
		t.Error("MatrixInverse should return error for singular matrix")
	}
}

func TestVectorMatrixMultiply(t *testing.T) {
	// v = [1, 0, 0, 0, 0] should give the first row of M
	var v [NumStates]float64
	v[0] = 1.0

	var M [NumStates][NumStates]float64
	M[0][0] = 0.2
	M[0][1] = 0.3
	M[0][2] = 0.1
	M[0][3] = 0.15
	M[0][4] = 0.25
	M[1][1] = 1.0
	M[2][2] = 1.0
	M[3][3] = 1.0
	M[4][4] = 1.0

	result := VectorMatrixMultiply(v, M)

	expected := [NumStates]float64{0.2, 0.3, 0.1, 0.15, 0.25}
	for i := 0; i < NumStates; i++ {
		if math.Abs(result[i]-expected[i]) > testTol {
			t.Errorf("v*M [%d]: got %f, want %f", i, result[i], expected[i])
		}
	}

	// Verify that a probability vector times a stochastic matrix sums to 1
	var v2 [NumStates]float64
	v2[0] = 0.2
	v2[1] = 0.3
	v2[2] = 0.1
	v2[3] = 0.15
	v2[4] = 0.25

	// Build a proper stochastic matrix
	var S [NumStates][NumStates]float64
	for i := 0; i < NumStates; i++ {
		remaining := 1.0
		for j := 0; j < NumStates-1; j++ {
			S[i][j] = remaining * 0.2
			remaining -= S[i][j]
		}
		S[i][NumStates-1] = remaining
	}

	result2 := VectorMatrixMultiply(v2, S)
	sum := 0.0
	for i := 0; i < NumStates; i++ {
		sum += result2[i]
	}
	if math.Abs(sum-1.0) > 1e-8 {
		t.Errorf("probability vector * stochastic matrix should sum to 1, got %f", sum)
	}
}

func TestVectorDiffNorm(t *testing.T) {
	a := [NumStates]float64{0.1, 0.5, 0.2, 0.15, 0.05}
	b := [NumStates]float64{0.2, 0.3, 0.25, 0.15, 0.1}

	norm := VectorDiffNorm(a, b)

	// Max absolute difference is |0.5 - 0.3| = 0.2
	if math.Abs(norm-0.2) > testTol {
		t.Errorf("VectorDiffNorm: got %f, want 0.2", norm)
	}

	// Same vector should have norm 0
	norm0 := VectorDiffNorm(a, a)
	if norm0 != 0 {
		t.Errorf("VectorDiffNorm(a, a): got %f, want 0", norm0)
	}
}
