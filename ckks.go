// ckks.go
package main

import (
	"encoding/json"
	"math"
	"math/cmplx"
	"math/rand"
	"syscall/js"
	"time"
)

// CKKS / RLWE Parameters
const M int = 8
const N_ring int = M / 2 // 4
const N_vec int = M / 4  // 2
const Q int64 = 1073741824 // 2^30
const Scale float64 = 64.0

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ---------------------------------------------------------
// COMPLEX MATH UTILS
// ---------------------------------------------------------

type Cmplx struct {
	Re float64 `json:"re"`
	Im float64 `json:"im"`
}

func toComplex128(c Cmplx) complex128 {
	return complex(c.Re, c.Im)
}

func toCmplxStruct(c complex128) Cmplx {
	return Cmplx{Re: real(c), Im: imag(c)}
}

func vdot(a, b []complex128) complex128 {
	var sum complex128 = 0
	for i := 0; i < len(a); i++ {
		sum += cmplx.Conj(a[i]) * b[i]
	}
	return sum
}

func transpose(mat [][]complex128) [][]complex128 {
	rows := len(mat)
	cols := len(mat[0])
	res := make([][]complex128, cols)
	for i := 0; i < cols; i++ {
		res[i] = make([]complex128, rows)
		for j := 0; j < rows; j++ {
			res[i][j] = mat[j][i]
		}
	}
	return res
}

func matrixVectorMul(mat [][]complex128, vec []complex128) []complex128 {
	res := make([]complex128, len(mat))
	for i := 0; i < len(mat); i++ {
		var sum complex128 = 0
		for j := 0; j < len(vec); j++ {
			sum += mat[i][j] * vec[j]
		}
		res[i] = sum
	}
	return res
}

func solveCmplx(A [][]complex128, b []complex128) []complex128 {
	n := len(A)
	mat := make([][]complex128, n)
	for i := 0; i < n; i++ {
		mat[i] = make([]complex128, n+1)
		copy(mat[i], A[i])
		mat[i][n] = b[i]
	}

	for i := 0; i < n; i++ {
		max := i
		for j := i + 1; j < n; j++ {
			if cmplx.Abs(mat[j][i]) > cmplx.Abs(mat[max][i]) {
				max = j
			}
		}
		mat[i], mat[max] = mat[max], mat[i]

		pivot := mat[i][i]
		for j := i; j <= n; j++ {
			mat[i][j] /= pivot
		}
		for j := 0; j < n; j++ {
			if i != j {
				factor := mat[j][i]
				for k := i; k <= n; k++ {
					mat[j][k] -= factor * mat[i][k]
				}
			}
		}
	}

	res := make([]complex128, n)
	for i := 0; i < n; i++ {
		res[i] = mat[i][n]
	}
	return res
}

// ---------------------------------------------------------
// CKKS ENCODER / DECODER
// ---------------------------------------------------------

func vandermonde(xi complex128, m int) [][]complex128 {
	n := m / 2
	matrix := make([][]complex128, n)
	for i := 0; i < n; i++ {
		root := cmplx.Pow(xi, complex(float64(2*i+1), 0))
		matrix[i] = make([]complex128, n)
		for j := 0; j < n; j++ {
			matrix[i][j] = cmplx.Pow(root, complex(float64(j), 0))
		}
	}
	return matrix
}

func piInverse(z []complex128) []complex128 {
	res := make([]complex128, len(z)*2)
	copy(res, z)
	for i := 0; i < len(z); i++ {
		res[len(z)+i] = cmplx.Conj(z[len(z)-1-i])
	}
	return res
}

func randRound(c float64) float64 {
	r := c - math.Floor(c)
	if rand.Float64() < (1 - r) {
		return math.Floor(c)
	}
	return math.Ceil(c)
}

func encodeCKKS(z []complex128) []int64 {
	piZ := piInverse(z)
	scaledPiZ := make([]complex128, len(piZ))
	for i, val := range piZ {
		scaledPiZ[i] = val * complex(Scale, 0)
	}

	xi := cmplx.Exp(complex(0, 2*math.Pi/float64(M)))
	sigmaRBasis := transpose(vandermonde(xi, M))

	coordinates := make([]complex128, len(sigmaRBasis))
	for i, b := range sigmaRBasis {
		num := vdot(scaledPiZ, b)
		den := vdot(b, b)
		coordinates[i] = complex(real(num)/real(den), 0)
	}

	roundedCoords := make([]complex128, len(coordinates))
	for i, c := range coordinates {
		roundedCoords[i] = complex(randRound(real(c)), 0)
	}

	roundedScalePiZi := matrixVectorMul(transpose(sigmaRBasis), roundedCoords)
	pCoeffsComplex := solveCmplx(vandermonde(xi, M), roundedScalePiZi)

	encodedPoly := make([]int64, len(pCoeffsComplex))
	for i, c := range pCoeffsComplex {
		encodedPoly[i] = int64(math.Round(real(c)))
	}
	return encodedPoly
}

func decodeCKKS(pCoeffs []int64) []complex128 {
	rescaledP := make([]complex128, len(pCoeffs))
	for i, c := range pCoeffs {
		rescaledP[i] = complex(float64(c)/Scale, 0)
	}

	xi := cmplx.Exp(complex(0, 2*math.Pi/float64(M)))
	n := M / 2
	zExt := make([]complex128, n)

	for i := 0; i < n; i++ {
		root := cmplx.Pow(xi, complex(float64(2*i+1), 0))
		var sum complex128 = 0
		for j, coeff := range rescaledP {
			sum += coeff * cmplx.Pow(root, complex(float64(j), 0))
		}
		zExt[i] = sum
	}

	// pi(z) limits to first M/4 elements
	return zExt[:M/4]
}

// ---------------------------------------------------------
// RLWE CRYPTOGRAPHY
// ---------------------------------------------------------

func modQ(val int64) int64 { return ((val % Q) + Q) % Q }
func centerModQ(val int64) int64 {
	v := modQ(val)
	if v > Q/2 {
		v -= Q
	}
	return v
}

func sampleUniformPoly() []int64 {
	poly := make([]int64, N_ring)
	for i := 0; i < N_ring; i++ {
		poly[i] = rand.Int63n(Q)
	}
	return poly
}

func sampleSmallPoly() []int64 {
	poly := make([]int64, N_ring)
	for i := 0; i < N_ring; i++ {
		r := rand.Float64()
		if r < 0.33 {
			poly[i] = 0
		} else if r < 0.66 {
			poly[i] = 1
		} else {
			poly[i] = Q - 1
		}
	}
	return poly
}

func polyAdd(p1, p2 []int64) []int64 {
	res := make([]int64, N_ring)
	for i := 0; i < N_ring; i++ {
		res[i] = modQ(p1[i] + p2[i])
	}
	return res
}

func polyMul(p1, p2 []int64) []int64 {
	res := make([]int64, 2*N_ring)
	for i := 0; i < N_ring; i++ {
		for j := 0; j < N_ring; j++ {
			res[i+j] += p1[i] * p2[j]
		}
	}
	out := make([]int64, N_ring)
	for i := 0; i < N_ring; i++ {
		out[i] = modQ(res[i] - res[i+N_ring]) // X^N = -1
	}
	return out
}

func keyGen() ([]int64, []int64, []int64) {
	sk := sampleSmallPoly()
	a := sampleUniformPoly()
	e := sampleSmallPoly()

	as := polyMul(a, sk)
	asPlusE := polyAdd(as, e)
	pk0 := make([]int64, N_ring)
	for i := 0; i < N_ring; i++ {
		pk0[i] = modQ(-asPlusE[i])
	}
	return sk, pk0, a
}

func encrypt(m []int64, pk0, pk1 []int64) ([]int64, []int64) {
	u := sampleSmallPoly()
	e1 := sampleSmallPoly()
	e2 := sampleSmallPoly()

	c0 := polyAdd(polyAdd(polyMul(pk0, u), e1), m)
	c1 := polyAdd(polyMul(pk1, u), e2)
	return c0, c1
}

func decrypt(c0, c1, sk []int64) []int64 {
	noisyPoly := polyAdd(c0, polyMul(c1, sk))
	res := make([]int64, N_ring)
	for i, val := range noisyPoly {
		res[i] = centerModQ(val)
	}
	return res
}

// ---------------------------------------------------------
// WASM EXPORTS
// ---------------------------------------------------------

func wasmEncode(this js.Value, args []js.Value) any {
	var input []Cmplx
	json.Unmarshal([]byte(args[0].String()), &input)
	
	z := make([]complex128, len(input))
	for i, c := range input {
		z[i] = toComplex128(c)
	}
	
	poly := encodeCKKS(z)
	bytes, _ := json.Marshal(poly)
	return string(bytes)
}

func wasmKeyGen(this js.Value, args []js.Value) any {
	sk, pk0, pk1 := keyGen()
	data := map[string]interface{}{"sk": sk, "pk0": pk0, "pk1": pk1}
	bytes, _ := json.Marshal(data)
	return string(bytes)
}

func wasmEncrypt(this js.Value, args []js.Value) any {
	var m, pk0, pk1 []int64
	json.Unmarshal([]byte(args[0].String()), &m)
	json.Unmarshal([]byte(args[1].String()), &pk0)
	json.Unmarshal([]byte(args[2].String()), &pk1)

	// Mod Q the message before encrypting
	for i := range m {
		m[i] = modQ(m[i])
	}

	c0, c1 := encrypt(m, pk0, pk1)
	data := map[string]interface{}{"c0": c0, "c1": c1}
	bytes, _ := json.Marshal(data)
	return string(bytes)
}

func wasmDecrypt(this js.Value, args []js.Value) any {
	var c0, c1, sk []int64
	json.Unmarshal([]byte(args[0].String()), &c0)
	json.Unmarshal([]byte(args[1].String()), &c1)
	json.Unmarshal([]byte(args[2].String()), &sk)

	noisyM := decrypt(c0, c1, sk)
	bytes, _ := json.Marshal(noisyM)
	return string(bytes)
}

func wasmDecode(this js.Value, args []js.Value) any {
	var noisyM []int64
	json.Unmarshal([]byte(args[0].String()), &noisyM)

	z := decodeCKKS(noisyM)
	out := make([]Cmplx, len(z))
	for i, c := range z {
		out[i] = toCmplxStruct(c)
	}
	bytes, _ := json.Marshal(out)
	return string(bytes)
}

func main() {
	js.Global().Set("goCkksEncode", js.FuncOf(wasmEncode))
	js.Global().Set("goCkksKeyGen", js.FuncOf(wasmKeyGen))
	js.Global().Set("goCkksEncrypt", js.FuncOf(wasmEncrypt))
	js.Global().Set("goCkksDecrypt", js.FuncOf(wasmDecrypt))
	js.Global().Set("goCkksDecode", js.FuncOf(wasmDecode))
	select {}
}