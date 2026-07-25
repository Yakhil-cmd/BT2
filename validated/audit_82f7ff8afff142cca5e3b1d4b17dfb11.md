Let me examine the critical difference between the two implementations more carefully.

Now I have a complete picture of the vulnerability. Let me analyze the critical divergence.

**Summary of findings:**

**gnark G2 `Unmarshal`** (`crypto/bn256/gnark/g2.go`, lines 55-60): checks both `IsOnCurve()` AND `IsInSubGroup()`.

**cloudflare G2 `Unmarshal`** (`crypto/bn256/cloudflare/bn256.go`, lines 281-283): checks ONLY `IsOnCurve()`. No subgroup check.

For BN254, the G2 cofactor h₂ > 1, meaning there exist points on the twist curve E'(Fp2) that are NOT in the prime-order subgroup. These points pass `IsOnCurve()` but fail `IsInSubGroup()`.

The divergence for such a point:
- **amd64/arm64 (gnark)**: `newTwistPoint` → `Unmarshal` → `IsInSubGroup()` fails → returns error → `runBn256Pairing` returns `(nil, error)` → EVM call fails/reverts
- **non-amd64/arm64 (cloudflare)**: `newTwistPoint` → `Unmarshal` → only `IsOnCurve()` checked → point accepted → `PairingCheck` computes pairing → returns boolean → EVM call succeeds

The existing fuzz test in `bn256_fuzz.go` only compares cloudflare vs. google, never gnark vs. cloudflare, so this divergence is untested.

---

### Title
Architecture-Dependent G2 Subgroup Check in `runBn256Pairing` Causes Consensus Divergence Between amd64/arm64 and Other Nodes — (`crypto/bn256/bn256_fast.go`, `crypto/bn256/bn256_slow.go`)

### Summary
The `runBn256Pairing` precompile (0x08) uses two different bn256 backends depending on build architecture: gnark on amd64/arm64 and cloudflare on all other architectures. The gnark G2 `Unmarshal` enforces a prime-order subgroup check (`IsInSubGroup()`), while the cloudflare G2 `Unmarshal` does not. A G2 point that lies on the twist curve E'(Fp2) but outside the prime-order subgroup will be rejected by gnark (returning an error, causing the precompile call to fail) but accepted by cloudflare (returning a boolean pairing result). This produces different EVM execution outcomes for the same transaction on different-architecture nodes, corrupting the state root and causing consensus divergence.

### Finding Description

The build-tag dispatch is:

`crypto/bn256/bn256_fast.go` (amd64/arm64): [1](#0-0) 

`crypto/bn256/bn256_slow.go` (all others): [2](#0-1) 

The gnark G2 `Unmarshal` enforces a subgroup check that cloudflare does not: [3](#0-2) 

The cloudflare G2 `Unmarshal` only checks `IsOnCurve()`: [4](#0-3) 

`runBn256Pairing` calls `newTwistPoint` which calls `Unmarshal` on the architecture-selected type: [5](#0-4) 

For BN254, the G2 cofactor h₂ is non-trivial (h₂ > 1). Points on E'(Fp2) outside the prime-order subgroup exist and are constructible with public knowledge. When such a point is submitted:

- **gnark path**: `Unmarshal` returns `errors.New("point is not in correct subgroup")` → `newTwistPoint` returns `(nil, err)` → `runBn256Pairing` returns `(nil, err)` → EVM treats the precompile call as failed (reverts)
- **cloudflare path**: `Unmarshal` returns `nil` error → `PairingCheck` computes the pairing over the non-subgroup point → returns `true` or `false` → EVM treats the precompile call as successful

The existing fuzz test only cross-checks cloudflare vs. google, never gnark vs. cloudflare: [6](#0-5) 

### Impact Explanation
A transaction calling precompile 0x08 with a crafted non-subgroup G2 point will revert on amd64/arm64 validators (gnark) and succeed on non-amd64/arm64 validators (cloudflare). The resulting receipts and state roots diverge between the two sets of honest nodes. This is a consensus divergence on honest nodes, satisfying the required impact gate. Any contract logic that depends on the pairing result (e.g., ZK-proof verifiers, signature schemes) will execute differently across the validator set, permanently splitting chain state.

### Likelihood Explanation
The attack requires only a single transaction submitted via public RPC. No privileged access, key compromise, or validator collusion is needed. The attacker only needs to know that the network has at least one non-amd64/arm64 node (a realistic assumption given the `bn256_slow.go` path exists in production code). Constructing a valid-on-curve but non-subgroup G2 point for BN254 is a standard cryptographic exercise using public parameters.

### Recommendation
Remove the `IsInSubGroup()` call from gnark's `G1.Unmarshal` and `G2.Unmarshal`, aligning with the cloudflare behavior and the EIP-197 specification, which does not mandate subgroup checks for the bn256 pairing precompile. Alternatively, add equivalent subgroup checks to the cloudflare `G2.Unmarshal`. Either fix must be applied consistently to both backends so that both accept or both reject the same set of inputs. Add a cross-backend property test that feeds identical inputs to both gnark and cloudflare and asserts equal error/result behavior.

### Proof of Concept

1. Compute a BN254 G2 point Q that is on the twist curve E'(Fp2) but satisfies r·Q ≠ O (a non-subgroup point). This is possible because h₂ > 1 for BN254.
2. Serialize Q into the 128-byte EVM format (x.A1 || x.A0 || y.A1 || y.A0, each 32 bytes big-endian).
3. Prepend any valid G1 point P (64 bytes) to form a 192-byte input.
4. Submit a transaction calling address `0x08` with this input.
5. On amd64/arm64 nodes: gnark's `g2.Unmarshal` calls `IsInSubGroup()` → returns false → error → precompile reverts → transaction receipt shows failure, no state change.
6. On non-amd64/arm64 nodes: cloudflare's `g2.Unmarshal` skips subgroup check → pairing computed → precompile returns a 32-byte boolean → transaction receipt shows success, state changes committed.
7. The two sets of nodes now hold different state roots for the same block, causing consensus divergence. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** crypto/bn256/bn256_fast.go (L9-25)
```go
//go:build amd64 || arm64

package bn256

import gnark "github.com/kaiachain/kaia/crypto/bn256/gnark"

// G1 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G1 = gnark.G1

// G2 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G2 = gnark.G2

// PairingCheck calculates the Optimal Ate pairing for a set of points.
func PairingCheck(a []*G1, b []*G2) bool {
	return gnark.PairingCheck(a, b)
```

**File:** crypto/bn256/bn256_slow.go (L9-25)
```go
//go:build !amd64 && !arm64

package bn256

import bn256 "github.com/kaiachain/kaia/crypto/bn256/cloudflare"

// G1 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G1 = bn256.G1

// G2 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G2 = bn256.G2

// PairingCheck calculates the Optimal Ate pairing for a set of points.
func PairingCheck(a []*G1, b []*G2) bool {
	return bn256.PairingCheck(a, b)
```

**File:** crypto/bn256/gnark/g2.go (L29-61)
```go
func (g *G2) Unmarshal(buf []byte) (int, error) {
	if len(buf) < 128 {
		return 0, errors.New("invalid G2 point size")
	}

	if allZeroes(buf[:128]) {
		// point at infinity
		g.inner.X.A0.SetZero()
		g.inner.X.A1.SetZero()
		g.inner.Y.A0.SetZero()
		g.inner.Y.A1.SetZero()
		return 128, nil
	}
	if err := g.inner.X.A1.SetBytesCanonical(buf[0:32]); err != nil {
		return 0, err
	}
	if err := g.inner.X.A0.SetBytesCanonical(buf[32:64]); err != nil {
		return 0, err
	}
	if err := g.inner.Y.A1.SetBytesCanonical(buf[64:96]); err != nil {
		return 0, err
	}
	if err := g.inner.Y.A0.SetBytesCanonical(buf[96:128]); err != nil {
		return 0, err
	}

	if !g.inner.IsOnCurve() {
		return 0, errors.New("point is not on curve")
	}
	if !g.inner.IsInSubGroup() {
		return 0, errors.New("point is not in correct subgroup")
	}
	return 128, nil
```

**File:** crypto/bn256/cloudflare/bn256.go (L241-285)
```go
// Unmarshal sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G2) Unmarshal(m []byte) ([]byte, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	if len(m) < 4*numBytes {
		return nil, errors.New("bn256: not enough data")
	}
	// Unmarshal the points and check their caps
	if e.p == nil {
		e.p = &twistPoint{}
	}
	var err error
	if err = e.p.x.x.Unmarshal(m); err != nil {
		return nil, err
	}
	if err = e.p.x.y.Unmarshal(m[numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.x.Unmarshal(m[2*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.y.Unmarshal(m[3*numBytes:]); err != nil {
		return nil, err
	}
	// Encode into Montgomery form and ensure it's on the curve
	montEncode(&e.p.x.x, &e.p.x.x)
	montEncode(&e.p.x.y, &e.p.x.y)
	montEncode(&e.p.y.x, &e.p.y.x)
	montEncode(&e.p.y.y, &e.p.y.y)

	if e.p.x.IsZero() && e.p.y.IsZero() {
		// This is the point at infinity.
		e.p.y.SetOne()
		e.p.z.SetZero()
		e.p.t.SetZero()
	} else {
		e.p.z.SetOne()
		e.p.t.SetOne()

		if !e.p.IsOnCurve() {
			return nil, errors.New("bn256: malformed point")
		}
	}
	return m[4*numBytes:], nil
```

**File:** blockchain/vm/contracts.go (L616-643)
```go
func runBn256Pairing(input []byte) ([]byte, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}
```

**File:** crypto/bn256/bn256_fuzz.go (L96-129)
```go
func FuzzPair(data []byte) int {
	// Ensure we have enough data in the first place
	if len(data) != 192 {
		return 0
	}
	// Ensure both libs can parse the curve point
	pc := new(cloudflare.G1)
	_, errc := pc.Unmarshal(data[:64])

	pg := new(google.G1)
	_, errg := pg.Unmarshal(data[:64])

	if (errc == nil) != (errg == nil) {
		panic("parse mismatch")
	} else if errc != nil {
		return 0
	}
	// Ensure both libs can parse the twist point
	tc := new(cloudflare.G2)
	_, errc = tc.Unmarshal(data[64:])

	tg := new(google.G2)
	_, errg = tg.Unmarshal(data[64:])

	if (errc == nil) != (errg == nil) {
		panic("parse mismatch")
	} else if errc != nil {
		return 0
	}
	// Pair the two points and ensure they result in the same output
	if cloudflare.PairingCheck([]*cloudflare.G1{pc}, []*cloudflare.G2{tc}) != google.PairingCheck([]*google.G1{pg}, []*google.G2{tg}) {
		panic("pair mismatch")
	}
	return 0
```
