The key question is whether the two backends diverge on the same input. Let me check the critical difference in validation logic between cloudflare and gnark.

The analysis is complete. The divergence is real and provable from the code.

**Root cause:** The two backends apply different validation during G2 point deserialization in `newTwistPoint`:

- **Cloudflare** (`crypto/bn256/cloudflare/bn256.go` G2 `Unmarshal`): checks `IsOnCurve()` only — no subgroup check.
- **Gnark** (`crypto/bn256/gnark/g2.go` G2 `Unmarshal`): checks `IsOnCurve()` **and** `IsInSubGroup()`.

On BN254, G2's cofactor h₂ ≠ 1, so points on E'(Fp²) can exist outside the prime-order subgroup. An attacker can craft such a point (on-curve, wrong subgroup) and submit it in a transaction calling precompile `0x08`.

- **Gnark nodes (amd64/arm64):** `newTwistPoint` → `IsInSubGroup()` fails → error returned → EVM CALL returns `(success=0, data=∅)`
- **Cloudflare nodes (non-amd64/arm64):** `newTwistPoint` → only `IsOnCurve()` checked → succeeds → `PairingCheck` runs → EVM CALL returns `(success=1, data=false32Byte)`

Any contract that branches on the CALL success flag will execute different code paths on the two architectures, producing different state roots → chain split.

---

### Title
Consensus Divergence via G2 Subgroup Check Asymmetry Between gnark and cloudflare BN256 Backends — (`crypto/bn256/gnark/g2.go`, `crypto/bn256/cloudflare/bn256.go`)

### Summary
The gnark backend (amd64/arm64) rejects G2 points not in the prime-order subgroup at parse time, while the cloudflare backend (non-amd64/arm64) accepts them. A single attacker-crafted transaction calling precompile `0x08` with such a point causes the EVM CALL to return `(success=0)` on gnark nodes and `(success=1, false)` on cloudflare nodes, producing divergent state roots and a chain split.

### Finding Description

`runBn256Pairing` calls `newTwistPoint` to deserialize each G2 input point: [1](#0-0) 

`newTwistPoint` delegates to `bn256.G2.Unmarshal`, which is architecture-selected at compile time.

**Gnark G2 Unmarshal** enforces both curve membership and subgroup membership: [2](#0-1) 

**Cloudflare G2 Unmarshal** enforces only curve membership: [3](#0-2) 

The build tags make this selection permanent per architecture: [4](#0-3) [5](#0-4) 

### Impact Explanation

For BN254, the G2 cofactor h₂ is non-trivial. A point can satisfy the curve equation over Fp² while having order r·h₂ (or any multiple of h₂ that is not a multiple of r), placing it outside the prime-order subgroup. When such a point is submitted:

- **Gnark path:** `Unmarshal` returns an error → `runBn256Pairing` returns `errBadPairingInput` → the EVM CALL to `0x08` returns `(success=0, returndata=∅)`.
- **Cloudflare path:** `Unmarshal` succeeds → `PairingCheck` is invoked → returns `false` → the EVM CALL returns `(success=1, returndata=false32Byte)`.

Any contract that inspects the CALL success flag (standard Solidity `address(0x08).call(...)` pattern) will branch differently on the two architectures, producing different storage writes, event emissions, or ether transfers, and ultimately different state roots. This is a consensus-breaking divergence satisfying the "invalid state transition / consensus divergence on honest nodes" impact gate.

### Likelihood Explanation

The attack requires only a single transaction submitted via public RPC. Constructing a G2 point on E'(Fp²) but outside the r-torsion subgroup is straightforward: take any generator of E'(Fp²) and multiply by h₂ (the cofactor) to obtain a non-trivial torsion point, or simply use a point of order h₂. No privileged access, key compromise, or validator collusion is needed. The attack is deterministic and reproducible.

### Recommendation

Add an `IsInSubGroup()` check to the cloudflare G2 `Unmarshal`, mirroring the gnark implementation:

```go
// crypto/bn256/cloudflare/bn256.go — G2.Unmarshal
if !e.p.IsOnCurve() {
    return nil, errors.New("bn256: malformed point")
}
if !e.p.IsInSubGroup() {
    return nil, errors.New("bn256: point not in correct subgroup")
}
```

Alternatively, add a cross-backend property test (feeding identical inputs to both `cloudflare.PairingCheck` and `gnark.PairingCheck` and asserting identical results including error/no-error) to the CI pipeline to catch future regressions.

### Proof of Concept

1. Compute a G2 point `P` on E'(Fp²) with order h₂ (not in the prime-order subgroup). This is public knowledge from the BN254 parameters.
2. Encode `P` in EVM format (128 bytes) and prepend a valid G1 point (e.g., the generator) to form a 192-byte pairing input.
3. Deploy a contract:
   ```solidity
   function exploit(bytes memory input) external returns (bool success, bytes memory data) {
       (success, data) = address(0x08).call(input);
       // On gnark nodes:     success=false, data=""
       // On cloudflare nodes: success=true,  data=abi.encode(false)
       if (success) { /* cloudflare path: write storage */ }
       else         { /* gnark path: different storage write */ }
   }
   ```
4. Submit the transaction. Gnark and cloudflare nodes will produce different storage roots, causing a chain split.

### Citations

**File:** blockchain/vm/contracts.go (L501-509)
```go
// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}
```

**File:** crypto/bn256/gnark/g2.go (L55-61)
```go
	if !g.inner.IsOnCurve() {
		return 0, errors.New("point is not on curve")
	}
	if !g.inner.IsInSubGroup() {
		return 0, errors.New("point is not in correct subgroup")
	}
	return 128, nil
```

**File:** crypto/bn256/cloudflare/bn256.go (L278-284)
```go
		e.p.z.SetOne()
		e.p.t.SetOne()

		if !e.p.IsOnCurve() {
			return nil, errors.New("bn256: malformed point")
		}
	}
```

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
