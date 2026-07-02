### Title
Cross-COA Signature Replay in `EVM.validateCOAOwnershipProof` Allows Proof Forgery for Any COA Owned by the Same Cadence Account - (File: fvm/evm/stdlib/contract.cdc)

---

### Summary

`EVM.validateCOAOwnershipProof` is an `access(all)` Cadence function that verifies a Flow account's ownership of a Cadence-Owned Account (COA). The function verifies that the provided signatures are valid over `signedData` and that the COA at the given `path` has the given `evmAddress`, but it never checks that `signedData` encodes `evmAddress`. Because the caller fully controls all parameters — including `path` and `evmAddress` — a signature produced by Alice to prove ownership of COA-A can be replayed by any third party to produce a valid proof for COA-B, a different COA owned by the same Cadence account. This is the direct analog of the Connext router-signature replay: a signed message is accepted multiple times for different targets because no binding between the signature and the specific target is enforced.

---

### Finding Description

**Root cause — `fvm/evm/stdlib/contract.cdc`, lines 1001–1116**

`validateCOAOwnershipProof` performs two independent checks:

1. Verify that the provided `signatures` are cryptographically valid over `signedData` using the account keys at `address`.
2. Verify that the COA resource stored at `path` on account `address` has an EVM address equal to `evmAddress`. [1](#0-0) [2](#0-1) 

These two checks are entirely independent. The signed message (`signedData`) is never required to commit to `evmAddress`. The code itself documents this gap: [3](#0-2) 

Because `validateCOAOwnershipProof` is `access(all)`, any Cadence script or transaction can call it with attacker-chosen `path` and `evmAddress` while reusing a signature that was originally produced for a different COA. [4](#0-3) 

**Exploit path**

Suppose a Cadence account `Alice` owns two COAs:
- COA-A at `/public/coa_a` with EVM address `0xAAAA...`
- COA-B at `/public/coa_b` with EVM address `0xBBBB...`

A legitimate protocol asks Alice to sign `signedData = H("authorize action X")` to prove ownership of COA-A. Alice produces `sig_A` over `signedData` with her account key.

An attacker observes `sig_A` on-chain (it is public once submitted). The attacker then calls:

```cadence
EVM.validateCOAOwnershipProof(
    address:    Alice_address,
    path:       /public/coa_b,      // ← attacker-chosen: COA-B's path
    signedData: signedData,          // ← same bytes Alice signed
    keyIndices: [0],
    signatures: [sig_A],             // ← Alice's signature, replayed
    evmAddress: 0xBBBB...           // ← attacker-chosen: COA-B's EVM address
)
```

The function returns `ValidationResult(isValid: true)` because:
- `sig_A` is a valid signature over `signedData` by Alice's key — check passes.
- The COA at `/public/coa_b` has address `0xBBBB...` — check passes.

The attacker has produced a valid proof that Alice authorized COA-B, using only a signature Alice produced for COA-A.

**Why the EVM-side path does not protect against this**

The EVM precompile `verifyCOAOwnershipProof(address,bytes32,bytes)` is called from `coa.sol`'s `isValidSignature` with `address(this)` hardcoded as the first argument: [5](#0-4) 

`DecodeABIEncodedProof` then sets `EVMAddress` to `address(this)` (the calling COA), so the EVM path is self-referential and not replayable across COAs. [6](#0-5) 

However, the Cadence-side `validateCOAOwnershipProof` is `access(all)` and accepts all parameters from the caller, including `evmAddress`. There is no enforcement that the EVM-side path is the only entry point.

---

### Impact Explanation

Any Cadence contract or off-chain authentication system that calls `EVM.validateCOAOwnershipProof` to gate a privileged action (e.g., asset withdrawal, governance vote, bridge authorization) can be bypassed. An attacker who observes a valid proof for COA-A can replay it to produce an accepted proof for COA-B owned by the same account, without the account holder's consent. This constitutes unauthorized authorization of on-chain actions on behalf of a COA the victim never intended to authorize.

The `COAOwnershipProof` struct is explicitly designed as an authentication primitive for cross-VM asset control: [7](#0-6) 

---

### Likelihood Explanation

- `validateCOAOwnershipProof` is `access(all)` — callable by any unprivileged Cadence script or transaction with no special keys or roles required.
- Signatures submitted in prior transactions are permanently visible on-chain and can be extracted by any observer.
- The precondition (account with multiple COAs) is explicitly anticipated by the protocol: the `CapabilityPath` parameter exists precisely to support multiple COAs per account.
- The attacker needs only to observe a prior valid proof submission and substitute the `path`/`evmAddress` pair.

---

### Recommendation

Enforce that `signedData` commits to `evmAddress` inside `validateCOAOwnershipProof` itself, rather than relying on callers to do so. Concretely, replace the raw `signedData` verification with a check that `signedData` is the hash of `evmAddress || application_data`, or alternatively, construct the message to verify as `hash(evmAddress || signedData)` inside the function before passing it to `keyList.verify`. This mirrors the Connext fix: track (or bind) the specific target so the same signature cannot be accepted for a different target.

---

### Proof of Concept

```cadence
// Attacker script — no privileged keys required
import EVM from 0xe467b9dd11fa00df  // mainnet EVM contract address

access(all)
fun main() {
    // sig_A was observed on-chain from a prior legitimate proof for COA-A
    let replayedSig: [UInt8] = [/* Alice's sig bytes */]
    let signedData:  [UInt8] = [/* the data Alice signed */]

    // Replay against COA-B (different path, different evmAddress)
    let result = EVM.validateCOAOwnershipProof(
        address:    0xAliceCadenceAddress,
        path:       /public/coa_b,
        signedData: signedData,
        keyIndices: [0],
        signatures: [replayedSig],
        evmAddress: [0xBB, 0xBB, /* ... COA-B bytes ... */]
    )
    // result.isValid == true  ← proof accepted for COA-B without Alice's consent
    assert(result.isValid, message: "replay succeeded")
}
``` [3](#0-2) [1](#0-0) [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L1095-1115)
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

        return ValidationResult(
            isValid: false,
            problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. Could not borrow the COA resource for account \(address)."
        )
```

**File:** fvm/evm/handler/coa/coa.sol (L118-118)
```text
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
```

**File:** fvm/evm/precompiles/arch.go (L219-242)
```go
func DecodeABIEncodedProof(input []byte) (*types.COAOwnershipProofInContext, error) {
	index := 0
	caller, err := ReadAddress(input, index)
	index += FixedSizeUnitDataReadSize
	if err != nil {
		return nil, err
	}

	hash, err := ReadBytes32(input, index)
	index += Bytes32DataReadSize
	if err != nil {
		return nil, err
	}

	encodedProof, err := ReadBytes(input, index)
	if err != nil {
		return nil, err
	}

	return types.NewCOAOwnershipProofInContext(
		hash,
		types.Address(caller),
		encodedProof,
	)
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
