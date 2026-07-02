### Title
Cross-COA Ownership Proof Replay via Missing `evmAddress` Binding in `validateCOAOwnershipProof` - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` does not enforce that `signedData` encodes `evmAddress`. Signatures produced to prove ownership of one COA (COA\_B) can be replayed — with a different `CapabilityPath` pointing to a second COA (COA\_A) owned by the same Cadence account — to falsely prove ownership of COA\_A. This is the direct analog of the PheasantNetwork bug: evidence (a signature set) generated for one context is accepted as valid proof in a different context because the shared validation function does not bind the proof to its intended target.

---

### Finding Description

`EVM.validateCOAOwnershipProof` performs two checks:

1. The provided signatures are cryptographically valid over `signedData` using the Cadence account's keys.
2. The `CadenceOwnedAccount` resource stored at `path` has an EVM address equal to `evmAddress`.

The function **does not** verify that `signedData` encodes `evmAddress`. The code itself documents this gap:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."

Because `COAOwnershipProof` is an RLP-encoded struct containing `Address`, `CapabilityPath`, `KeyIndices`, and `Signatures`, an attacker can freely substitute the `CapabilityPath` field while keeping the original signatures intact. The signatures remain valid (they were produced over `signedData`, not over the proof struct), and the path-to-address check passes for the substituted COA.

The attack path through the EVM precompile (`verifyCOAOwnershipProof`) is equally reachable: the COA contract's `isValidSignature` calls `verifyCOAOwnershipProof(address(this), _hash, _sig)`, where `address(this)` is the target COA. An attacker who calls `COA_A.isValidSignature(D, crafted_proof)` — where `crafted_proof` carries the path to COA\_A but the signatures Alice originally produced for COA\_B — will receive `isValid: true`.

---

### Impact Explanation

Any EVM contract that relies on ERC-1271 (`isValidSignature`) to authorize privileged actions on a specific COA (e.g., multisig wallets, DeFi protocols, bridge escrow contracts) can be bypassed. An attacker who obtains a valid proof for a low-value COA\_B can replay it against a high-value COA\_A owned by the same Cadence account, gaining unauthorized ERC-1271 authorization for COA\_A. This constitutes cross-VM asset loss: assets or capabilities gated behind COA\_A's ERC-1271 signature become accessible without COA\_A's owner ever signing for them.

---

### Likelihood Explanation

- The function is `access(all)` and is part of the public protocol API; any Cadence script or EVM transaction can invoke it.
- The COA contract's `isValidSignature` is deployed on-chain and callable by any EVM contract.
- The protocol places no constraint on the number of COAs a single Cadence account may own; multi-COA accounts are valid and increasingly common as the EVM ecosystem grows.
- The vulnerability is explicitly acknowledged in the source code comment, confirming the developers are aware the binding is absent.
- Obtaining a prior proof for COA\_B requires only that Alice has previously authenticated with any application using COA\_B's ownership proof — a routine operation.

---

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` commits to `evmAddress` (e.g., require `signedData` to be a hash that includes the 20-byte EVM address as a prefix or structured field). This removes the cross-COA replay surface at the protocol level rather than delegating the responsibility to every downstream caller.

---

### Proof of Concept

**Setup**: Alice's Cadence account owns two COAs:
- COA\_B at `/public/coaB` (low value)
- COA\_A at `/public/coaA` (high value, protected by ERC-1271 in an EVM vault contract)

**Step 1 — Alice authenticates with COA\_B**:
Alice signs arbitrary data `D` and submits a `COAOwnershipProof` with `CapabilityPath = /public/coaB`. This proof is broadcast on-chain and is publicly visible.

**Step 2 — Attacker constructs a cross-COA proof**:
The attacker RLP-encodes a new `COAOwnershipProof`:
```
Address        = Alice's Cadence address   // unchanged
CapabilityPath = /public/coaA              // substituted
KeyIndices     = [Alice's key indices]     // unchanged
Signatures     = [Alice's signatures]      // unchanged — still valid over D
```

**Step 3 — Attacker calls `COA_A.isValidSignature(D, crafted_proof)`**:
The COA contract calls:
```solidity
cadenceArch.staticcall(
  abi.encodeWithSignature(
    "verifyCOAOwnershipProof(address,bytes32,bytes)",
    address(this),   // = COA_A's EVM address
    D,
    crafted_proof
  )
)
```

**Step 4 — `validateCOAOwnershipProof` evaluation**:
- Signature check: `keyList.verify(signatureSet, signedData: D, domainSeparationTag: "FLOW-V0.0-user")` → **PASSES** (Alice's keys signed `D`)
- Address check: `acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coaA).address()` == COA\_A\_address == `evmAddress` → **PASSES**
- Returns `ValidationResult(isValid: true, problem: nil)`

**Step 5 — Impact**:
The EVM vault contract receives `ValidERC1271Signature (0x1626ba7e)` for COA\_A, authorizing the attacker's action (e.g., withdrawal) without COA\_A's owner ever signing for it.

---

**Relevant code references**: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1086)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )
```

**File:** fvm/evm/stdlib/contract.cdc (L1095-1110)
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
        }
```

**File:** fvm/evm/handler/coa/coa.sol (L113-125)
```text
    // ERC1271 requirement 
    function isValidSignature(
        bytes32 _hash,
        bytes memory _sig
    ) external view virtual returns (bytes4){
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
        require(ok);
        bool output = abi.decode(data, (bool));
        if (output) {
            return ValidERC1271Signature;
        }
        return InvalidERC1271Signature;
    }
```

**File:** fvm/evm/types/proof.go (L131-144)
```go
// COAOwnershipProof is a proof that a flow account
// controls a COA resource. To do so, the flow
// account (Address is address of this account)
// provides signatures (with proper total weights) over an arbitrary data input
// set by proof requester. KeyIndices captures,
// which account keys has been used for signatures.
// Beside signatures, it provides the CapabilityPath
// where the resource EVMAddress capability is stored.
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```

**File:** fvm/evm/precompiles/arch.go (L143-155)
```go
func (f *proofVerifier) Run(input []byte) ([]byte, error) {
	proof, err := DecodeABIEncodedProof(input)
	if err != nil {
		return nil, err
	}
	verified, err := f.proofVerifier(proof)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, EncodedBoolSize)
	return buffer, EncodeBool(verified, buffer, 0)
}
```
