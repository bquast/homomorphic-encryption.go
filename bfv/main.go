package main

import (
	"encoding/json"
	"math/rand"
	"syscall/js"
	"time"
)

// BFV Parameters
const N int64 = 8
const Q int64 = 12289
const T int64 = 256
const Delta int64 = Q / T

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ---------------------------------------------------------
// PURE FUNCTIONS: Polynomial Math (FP Style, no OOP)
// ---------------------------------------------------------

func modQ(val int64) int64 {
	return ((val % Q) + Q) % Q
}

func sampleUniformPoly() []int64 {
	poly := make([]int64, N)
	for i := int64(0); i < N; i++ {
		poly[i] = rand.Int63n(Q)
	}
	return poly
}

func sampleSmallPoly() []int64 {
	poly := make([]int64, N)
	for i := int64(0); i < N; i++ {
		r := rand.Float64()
		if r < 0.33 {
			poly[i] = 0
		} else if r < 0.66 {
			poly[i] = 1
		} else {
			poly[i] = Q - 1 // represents -1 mod Q
		}
	}
	return poly
}

func polyAdd(p1, p2 []int64) []int64 {
	res := make([]int64, N)
	for i := int64(0); i < N; i++ {
		res[i] = modQ(p1[i] + p2[i])
	}
	return res
}

func polySub(p1, p2 []int64) []int64 {
	res := make([]int64, N)
	for i := int64(0); i < N; i++ {
		res[i] = modQ(p1[i] - p2[i])
	}
	return res
}

func polyMul(p1, p2 []int64) []int64 {
	res := make([]int64, 2*N)
	for i := int64(0); i < N; i++ {
		for j := int64(0); j < N; j++ {
			res[i+j] += p1[i] * p2[j]
		}
	}
	out := make([]int64, N)
	for i := int64(0); i < N; i++ {
		// x^N = -1, so x^(N+i) flips sign and adds to x^i
		out[i] = modQ(res[i] - res[i+N])
	}
	return out
}

// ---------------------------------------------------------
// BFV Core Logic
// ---------------------------------------------------------

func keyGen() ([]int64, []int64, []int64) {
	s := sampleSmallPoly()
	a := sampleUniformPoly()
	e := sampleSmallPoly()

	// pk0 = -(a*s + e) mod Q
	as := polyMul(a, s)
	asPlusE := polyAdd(as, e)
	pk0 := make([]int64, N)
	for i := int64(0); i < N; i++ {
		pk0[i] = modQ(-asPlusE[i])
	}
	pk1 := a

	return s, pk0, pk1
}

func encrypt(m int64, pk0, pk1 []int64) ([]int64, []int64) {
	scaledM := make([]int64, N)
	scaledM[0] = modQ(Delta * m)

	u := sampleSmallPoly()
	e1 := sampleSmallPoly()
	e2 := sampleSmallPoly()

	// c0 = pk0*u + e1 + Delta*m
	pk0u := polyMul(pk0, u)
	c0 := polyAdd(polyAdd(pk0u, e1), scaledM)

	// c1 = pk1*u + e2
	pk1u := polyMul(pk1, u)
	c1 := polyAdd(pk1u, e2)

	return c0, c1
}

func decrypt(c0, c1, sk []int64) int64 {
	// c0 + c1*s
	c1s := polyMul(c1, sk)
	noisyPoly := polyAdd(c0, c1s)

	noisyConst := noisyPoly[0]
	numerator := (noisyConst * T) + (Q / 2)
	decrypted := (numerator / Q) % T

	return decrypted
}

// ---------------------------------------------------------
// WASM Interop Wrappers
// ---------------------------------------------------------

func wasmKeyGen(this js.Value, args []js.Value) any {
	sk, pk0, pk1 := keyGen()
	data := map[string]interface{}{
		"sk":  sk,
		"pk0": pk0,
		"pk1": pk1,
	}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func wasmEncrypt(this js.Value, args []js.Value) any {
	m := int64(args[0].Int())
	pk0Str := args[1].String()
	pk1Str := args[2].String()

	var pk0 []int64
	var pk1 []int64
	json.Unmarshal([]byte(pk0Str), &pk0)
	json.Unmarshal([]byte(pk1Str), &pk1)

	c0, c1 := encrypt(m, pk0, pk1)
	data := map[string]interface{}{
		"c0": c0,
		"c1": c1,
	}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func wasmAddCiphertexts(this js.Value, args []js.Value) any {
	c0aStr, c1aStr := args[0].String(), args[1].String()
	c0bStr, c1bStr := args[2].String(), args[3].String()

	var c0a, c1a, c0b, c1b []int64
	json.Unmarshal([]byte(c0aStr), &c0a)
	json.Unmarshal([]byte(c1aStr), &c1a)
	json.Unmarshal([]byte(c0bStr), &c0b)
	json.Unmarshal([]byte(c1bStr), &c1b)

	c0 := polyAdd(c0a, c0b)
	c1 := polyAdd(c1a, c1b)

	data := map[string]interface{}{
		"c0": c0,
		"c1": c1,
	}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func wasmDecrypt(this js.Value, args []js.Value) any {
	c0Str, c1Str := args[0].String(), args[1].String()
	skStr := args[2].String()

	var c0, c1, sk []int64
	json.Unmarshal([]byte(c0Str), &c0)
	json.Unmarshal([]byte(c1Str), &c1)
	json.Unmarshal([]byte(skStr), &sk)

	result := decrypt(c0, c1, sk)
	return int(result)
}

func main() {
	// Expose functions to the JS global scope
	js.Global().Set("goBfvKeyGen", js.FuncOf(wasmKeyGen))
	js.Global().Set("goBfvEncrypt", js.FuncOf(wasmEncrypt))
	js.Global().Set("goBfvAdd", js.FuncOf(wasmAddCiphertexts))
	js.Global().Set("goBfvDecrypt", js.FuncOf(wasmDecrypt))

	// Block forever so Go WASM doesn't exit
	select {}
}