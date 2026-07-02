### Title
Missing `evmAddress` Binding in COA Ownership Proof Signed Data Enables Cross-COA Signature Replay - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies signatures over caller-supplied `signedData` without enforcing that `signedData` encodes the target `evmAddress`. This is the direct Flow analog of the EIP712 "wrong verifying contract" bug: the signed payload omits the binding to the specific COA being authenticated, so a signature produced for one COA can be replayed to prove ownership of any other COA controlled by the same Cadence account.

---

### Finding Description

In `fvm/evm/stdlib/contract.cdc`, `validateCOAOwnershipProof` (line 1011) performs two independent checks:

1. **Signature check** (line 1082–1086): verifies that the provided signatures are valid over `signedData` using the hardcoded domain tag `"FLOW-V0.0-user"`.
2. **COA address check** (lines 1095–1105): verifies that the COA resource stored at the caller-supplied `path` has an EVM address matching the caller-supplied `evmAddress`. [1](#0-0) 

The critical flaw is that these two checks are **decoupled**: the signature is over `signedData`, but `signedData` is never required to encode `evmAddress`. The `evmAddress` and `path` parameters are fully attacker-controlled in any direct Cadence-side invocation of this `access(all)` function.

The code itself acknowledges this at lines 1003–1009: [2](#0-1) 

The function is `access(all)`, meaning any Cadence script or transaction can call it with arbitrary `evmAddress` and `path` values: [3](#0-2) 

The `COAOwnershipProof` struct (embedded in `COAOwnershipProofInContext`) contains the Cadence account `Address`, `CapabilityPath`, `KeyIndices`, and `Signatures`, but **not** the `evmAddress` — it is a separate field passed alongside the proof: [4](#0-3) 

This mirrors the EIP712 bug exactly: the "verifying contract" (`evmAddress`) is not bound into the signed payload, so signatures are portable across all COAs owned by the same Cadence account.

---

### Impact Explanation

If a Cadence account controls two COAs — COA\_A (published at `/public/coa_a`) and COA\_B (published at `/public/coa_b`) — a valid ownership proof for COA\_A (signatures over some `signedData = H`) can be replayed to prove ownership of COA\_B:

- Signature verification passes: same account keys, same `H`, same domain tag `"FLOW-V0.0-user"`.
- COA address check passes: the attacker supplies `evmAddress = COA_B.address` and `path = /public/coa_b`, which match each other.
- `validateCOAOwnershipProof` returns `isValid: true` for COA\_B, even though the account owner only intended to authorize COA\_A.

Any on-chain Cadence protocol that calls `EVM.validateCOAOwnershipProof` to gate access to COA-specific assets or capabilities is vulnerable to this cross-COA replay. The EVM precompile path (`verifyCOAOwnershipProof` in `coa.sol`) is not directly exploitable because the `evmAddress` argument is hardcoded to `address(this)`: [5](#0-4) 

However, the Cadence-side `validateCOAOwnershipProof` is reachable by any unprivileged transaction sender or script author with no restrictions.

---

### Likelihood Explanation

The attack requires:
1. A Cadence account that controls more than one COA (uncommon today but not prohibited by the protocol).
2. A Cadence-side protocol that uses `EVM.validateCOAOwnershipProof` to gate access to COA-specific on-chain resources.
3. An observable prior ownership proof for one of the account's COAs (e.g., emitted in a transaction or passed as a script argument).

All three conditions are reachable by an unprivileged attacker with no special keys or node access. The likelihood is **medium**: multi-COA accounts are not the norm today, but the protocol places no restriction on them, and the attack surface grows as more Cadence protocols integrate COA ownership proofs.

---

### Recommendation

Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof` itself, rather than relying on callers to do so. Concretely, before the signature verification step, prepend or hash-commit `evmAddress` into the data that is actually verified:

```cadence
// Bind evmAddress into the verified payload
let boundData = evmAddress.concat(signedData)
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: boundData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

This is the direct analog of the EIP712 fix: bind the "verifying contract" (here, the COA's EVM address) into the signed payload so that signatures are not portable across COAs. The fix must be applied at the protocol level, not delegated to callers, because the function is `access(all)` and callers cannot be trusted to enforce this invariant.

---

### Proof of Concept

**Setup**: Cadence account `A` controls COA\_A (at `/public/coa_a`, EVM address `0xAAAA`) and COA\_B (at `/public/coa_b`, EVM address `0xBBBB`).

**Step 1**: A legitimate protocol asks account `A` to prove ownership of COA\_A by signing `signedData = H` (an arbitrary 32-byte hash). Account `A` signs `H` with key index 0, producing `sig`.

**Step 2**: The proof `{Address: A, CapabilityPath: "coa_a", KeyIndices: [0], Signatures: [sig]}` is submitted on-chain and becomes observable.

**Step 3**: An attacker constructs a replay call:

```cadence
EVM.validateCOAOwnershipProof(
    address: A,
    path: /public/coa_b,   // ← attacker-controlled: points to COA_B
    signedData: H,          // ← same signedData, no evmAddress binding
    keyIndices: [0],
    signatures: [sig],      // ← same signature
    evmAddress: [0xBB, 0xBB, ...] // ← attacker-controlled: COA_B's address
)
```

**Step 4**: Signature verification at line 1082 passes — `sig` is a valid signature over `H` under account `A`'s key with tag `"FLOW-V0.0-user"`. [1](#0-0) 

**Step 5**: COA address check at line 1095 passes — the COA at `/public/coa_b` has EVM address `0xBBBB`, which matches the attacker-supplied `evmAddress`. [6](#0-5) 

**Result**: `validateCOAOwnershipProof` returns `ValidationResult(isValid: true, problem: nil)` for COA\_B, using a signature that account `A` produced solely to authorize COA\_A. Any protocol gating COA\_B-specific asset access on this result is bypassed.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1001-1009)
```text
    /// validateCOAOwnershipProof validates a COA ownership proof.
    ///
    /// Note: this function does not enforce that `signedData` includes `evmAddress`.
    /// In principle, a signature produced for one purpose could be replayed here against
    /// a different COA owned by the same Cadence account. In practice this is low-risk:
    /// the EVM-side precompile (verifyCOAOwnershipProof) always passes the calling COA's
    /// address as the evmAddress argument, and Flow wallets historically create at most one
    /// COA per account. Callers building off-chain authentication flows on top of this
    /// function should ensure `signedData` encodes `evmAddress` to prevent cross-address replay.
```

**File:** fvm/evm/stdlib/contract.cdc (L1010-1018)
```text
    access(all)
    fun validateCOAOwnershipProof(
        address: Address,
        path: PublicPath,
        signedData: [UInt8],
        keyIndices: [UInt64],
        signatures: [[UInt8]],
        evmAddress: [UInt8; 20]
    ): ValidationResult {
```

**File:** fvm/evm/stdlib/contract.cdc (L1082-1086)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )
```

**File:** fvm/evm/stdlib/contract.cdc (L1095-1109)
```text
        if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
            // verify evm address matching — capture bytes once to avoid redundant borrow
            let coaAddressBytes = coaRef.address().bytes
            for index, item in coaAddressBytes {
                if item != evmAddress[index] {
                    return ValidationResult(
                        isValid: false,
                        problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. The provided evm address does not match the account's COA address."
                    )
                }
            }
            return ValidationResult(
                isValid: true,
                problem: nil
            )
```

**File:** fvm/evm/types/proof.go (L102-106)
```go
type COAOwnershipProofInContext struct {
	COAOwnershipProof
	SignedData SignedData
	EVMAddress Address
}
```

**File:** fvm/evm/handler/coa/coa.sol (L118-118)
```text
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
```
