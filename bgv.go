package main

import (
	"encoding/json"
	"math/rand"
	"syscall/js"
	"time"
)

// BGV Parameters from Python Script
const N int64 = 16
const P int64 = 7
const Q int64 = 868

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ---------------------------------------------------------
// PURE FUNCTIONS: Polynomial Math (FP Style, no OOP)
// ---------------------------------------------------------

func modQ(val int64) int64 {
	return ((val % Q) + Q) % Q
}

func modP(val int64) int64 {
	return ((val % P) + P) % P
}

// centeredModQ lifts a value from [0, Q-1] into [-Q/2, Q/2]
// This is critical for BGV decryption to handle negative noise!
func centeredModQ(val int64) int64 {
	v := modQ(val)
	if v > Q/2 {
		v -= Q
	}
	return v
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
			poly[i] = -1 // Used conceptually, will be modded later
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
		// x^N = -1, so x^(N+i) flips sign
		out[i] = modQ(res[i] - res[i+N])
	}
	return out
}

func polyMulScalar(poly []int64, scalar int64) []int64 {
	res := make([]int64, N)
	for i := int64(0); i < N; i++ {
		res[i] = modQ(poly[i] * scalar)
	}
	return res
}

// ---------------------------------------------------------
// BGV Core Logic
// ---------------------------------------------------------

func keyGen() ([]int64, []int64, []int64) {
	s := sampleSmallPoly()
	a := sampleUniformPoly()
	e := sampleSmallPoly()

	// pk0 = -(a*s + p*e) mod Q
	as := polyMul(a, s)
	pe := polyMulScalar(e, P)
	asPlusPe := polyAdd(as, pe)
	
	pk0 := make([]int64, N)
	for i := int64(0); i < N; i++ {
		pk0[i] = modQ(-asPlusPe[i])
	}
	pk1 := a

	return s, pk0, pk1
}

func encrypt(m int64, pk0, pk1 []int64) ([]int64, []int64) {
	mPoly := make([]int64, N)
	mPoly[0] = modP(m) // In BGV, message is NOT scaled by Delta!

	u := sampleSmallPoly()
	e1 := sampleSmallPoly()
	e2 := sampleSmallPoly()

	// ct0 = pk0*u + p*e1 + m
	pk0u := polyMul(pk0, u)
	pe1 := polyMulScalar(e1, P)
	ct0 := polyAdd(polyAdd(pk0u, pe1), mPoly)

	// ct1 = pk1*u + p*e2
	pk1u := polyMul(pk1, u)
	pe2 := polyMulScalar(e2, P)
	ct1 := polyAdd(pk1u, pe2)

	return ct0, ct1
}

func decrypt(ct0, ct1, sk []int64) int64 {
	// noisy = ct0 + ct1*s mod Q
	ct1s := polyMul(ct1, sk)
	noisyPoly := polyAdd(ct0, ct1s)

	// Extract constant coefficient
	noisyConst := noisyPoly[0]
	
	// Center the value around 0 to handle negative noise
	centered := centeredModQ(noisyConst)
	
	// Modulo P recovers the message (error drops out because it was a multiple of P)
	m := modP(centered)

	return m
}

// ---------------------------------------------------------
// WASM Interop Wrappers
// ---------------------------------------------------------

func wasmKeyGen(this js.Value, args []js.Value) any {
	sk, pk0, pk1 := keyGen()
	data := map[string]interface{}{"sk": sk, "pk0": pk0, "pk1": pk1}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func wasmEncrypt(this js.Value, args []js.Value) any {
	m := int64(args[0].Int())
	var pk0, pk1 []int64
	json.Unmarshal([]byte(args[1].String()), &pk0)
	json.Unmarshal([]byte(args[2].String()), &pk1)

	ct0, ct1 := encrypt(m, pk0, pk1)
	data := map[string]interface{}{"ct0": ct0, "ct1": ct1}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func wasmAddCiphertexts(this js.Value, args []js.Value) any {
	var ctA0, ctA1, ctB0, ctB1 []int64
	json.Unmarshal([]byte(args[0].String()), &ctA0)
	json.Unmarshal([]byte(args[1].String()), &ctA1)
	json.Unmarshal([]byte(args[2].String()), &ctB0)
	json.Unmarshal([]byte(args[3].String()), &ctB1)

	ct0 := polyAdd(ctA0, ctB0)
	ct1 := polyAdd(ctA1, ctB1)

	data := map[string]interface{}{"ct0": ct0, "ct1": ct1}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func wasmSubCiphertexts(this js.Value, args []js.Value) any {
	var ctA0, ctA1, ctB0, ctB1 []int64
	json.Unmarshal([]byte(args[0].String()), &ctA0)
	json.Unmarshal([]byte(args[1].String()), &ctA1)
	json.Unmarshal([]byte(args[2].String()), &ctB0)
	json.Unmarshal([]byte(args[3].String()), &ctB1)

	ct0 := polySub(ctA0, ctB0)
	ct1 := polySub(ctA1, ctB1)

	data := map[string]interface{}{"ct0": ct0, "ct1": ct1}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func wasmDecrypt(this js.Value, args []js.Value) any {
	var ct0, ct1, sk []int64
	json.Unmarshal([]byte(args[0].String()), &ct0)
	json.Unmarshal([]byte(args[1].String()), &ct1)
	json.Unmarshal([]byte(args[2].String()), &sk)

	result := decrypt(ct0, ct1, sk)
	return int(result)
}

func main() {
	js.Global().Set("goBgvKeyGen", js.FuncOf(wasmKeyGen))
	js.Global().Set("goBgvEncrypt", js.FuncOf(wasmEncrypt))
	js.Global().Set("goBgvAdd", js.FuncOf(wasmAddCiphertexts))
	js.Global().Set("goBgvSub", js.FuncOf(wasmSubCiphertexts))
	js.Global().Set("goBgvDecrypt", js.FuncOf(wasmDecrypt))

	select {}
}