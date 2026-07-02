### Title
`EVM.validateCOAOwnershipProof` Does Not Bind `signedData` to `evmAddress`, Enabling Cross-COA Signature Replay - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies that a set of Flow account signatures are valid over `signedData`, then checks that the COA resource at a caller-supplied `path` matches the provided `evmAddress`. Because `signedData` is never required to commit to `evmAddress`, and because the `CapabilityPath` inside the RLP-encoded proof is not covered by the signatures, an attacker can take a legitimate signature produced for COA-A and replay it against COA-B owned by the same Cadence account — passing ERC-1271 verification for COA-B without the owner's consent.

---

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs two independent checks:

1. Verify that the supplied signatures are valid over `signedData` using the account's keys.
2. Borrow the `CadenceOwnedAccount` resource from the caller-supplied `path` and confirm its `.address()` equals `evmAddress`. [1](#0-0) 

Neither check binds `signedData` to `evmAddress`. The code itself acknowledges this in a developer note: [2](#0-1) 

The COA's ERC-1271 implementation in `coa.sol` calls the Cadence Arch precompile as:

```solidity
cadenceArch.staticcall(
    abi.encodeWithSignature(
        "verifyCOAOwnershipProof(address,bytes32,bytes)",
        address(this), _hash, _sig
    )
);
``` [3](#0-2) 

The `_sig` argument is an RLP-encoded `COAOwnershipProof` struct that contains `CapabilityPath`: [4](#0-3) 

Because the signatures inside the proof are over `signedData` (i.e., `_hash`) and **not** over the proof structure itself, an attacker can freely substitute the `CapabilityPath` field — redirecting the capability lookup from `/public/coaA` to `/public/coaB` — without invalidating any signature. The `evmAddress` passed by the precompile is always `address(this)` (the calling COA), so step 2 of the check will succeed for COA-B as long as Alice has COA-B published at the attacker-chosen path.

The root cause is structurally identical to H-03: a critical binding parameter (`evmAddress` / `CapabilityPath`) is excluded from the commitment that is actually signed, so an attacker can substitute their own value while keeping the signature valid.

---

### Impact Explanation

An attacker who obtains any valid Flow-account signature over an arbitrary 32-byte hash `H` (e.g., observed from a prior on-chain ERC-1271 interaction with COA-A) can construct a modified proof pointing to COA-B and call `isValidSignature(H, modified_proof)` on COA-B. Any EVM smart contract that relies on ERC-1271 to gate asset transfers or approvals will treat this as a valid authorization from the COA-B owner. Concretely:

- Unauthorized ERC-20/ERC-721 approvals or permit signatures can be forged for COA-B.
- DeFi protocols using ERC-1271 for order authorization (e.g., off-chain order books, permit-based vaults) can be tricked into executing transactions on behalf of COA-B without the owner's consent, draining assets held by or approved to COA-B.

---

### Likelihood Explanation

The attack requires a Cadence account that owns **more than one** COA. The code comment notes this is historically rare. However:

- `EVM.createCadenceOwnedAccount()` is `access(all)` with no per-account limit; any transaction can create additional COAs.
- As Flow EVM adoption grows, multi-COA accounts (e.g., one per dApp) become more common.
- The attacker only needs to observe one prior ERC-1271 interaction from the victim's COA-A to obtain a replayable `(signedData, proof)` pair — all data is on-chain.
- No privileged access, key compromise, or node control is required; a standard unprivileged EVM transaction suffices.

---

### Recommendation

Enforce that `signedData` commits to `evmAddress` before returning `isValid: true`. The simplest protocol-level fix is to require callers to sign `keccak256(abi.encode(evmAddress, applicationData))` rather than raw application data. Alternatively, `validateCOAOwnershipProof` can verify that the 20-byte `evmAddress` appears verbatim inside `signedData` before accepting the proof. The EVM-side `isValidSignature` wrapper in `coa.sol` should pass `abi.encode(address(this), _hash)` as the signed payload rather than `_hash` alone. [5](#0-4) 

---

### Proof of Concept

**Setup:**
- Alice owns two COAs: COA-A (EVM address `0xAAAA…`) stored at `/storage/coaA`, published at `/public/coaA`; COA-B (EVM address `0xBBBB…`) stored at `/storage/coaB`, published at `/public/coaB`.

**Step 1 — Obtain a legitimate proof for COA-A:**
Alice signs hash `H` (e.g., an ERC-1271 order hash on a DEX) and submits proof `P_A`:
```
P_A = RLP({ Address: Alice, CapabilityPath: "coaA", KeyIndices: [0], Signatures: [sig_H] })
```
The DEX calls `COA-A.isValidSignature(H, P_A)` → returns `0x1626ba7e` (valid).

**Step 2 — Attacker constructs a modified proof for COA-B:**
```
P_B = RLP({ Address: Alice, CapabilityPath: "coaB", KeyIndices: [0], Signatures: [sig_H] })
```
Only `CapabilityPath` changed; `sig_H` is identical and still valid over `H`.

**Step 3 — Attacker calls `isValidSignature` on COA-B:**
```solidity
ICOA(COA_B).isValidSignature(H, P_B)
```
Inside `coa.sol`:
```solidity
cadenceArch.staticcall(
    "verifyCOAOwnershipProof(address,bytes32,bytes)",
    address(COA_B),   // 0xBBBB…
    H,
    P_B
)
```
`validateCOAOwnershipProof` is invoked with `evmAddress = 0xBBBB…`, `path = /public/coaB`, `signedData = H`, `signatures = [sig_H]`.

- `sig_H` verifies over `H` with Alice's key ✓
- COA at `/public/coaB` has address `0xBBBB…` ✓
- Returns `isValid: true` ✓

**Result:** The DEX (or any ERC-1271 consumer) accepts `H` as a valid authorization from COA-B, even though Alice only ever signed it for COA-A. Any asset transfer or approval gated on this check executes against COA-B without Alice's consent. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L1011-1018)
```text
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

**File:** fvm/evm/types/proof.go (L102-118)
```go
type COAOwnershipProofInContext struct {
	COAOwnershipProof
	SignedData SignedData
	EVMAddress Address
}

func NewCOAOwnershipProofInContext(sd []byte, addr Address, encodedProof []byte) (*COAOwnershipProofInContext, error) {
	proof, err := COAOwnershipProofFromEncoded(encodedProof)
	if err != nil {
		return nil, err
	}
	return &COAOwnershipProofInContext{
		COAOwnershipProof: *proof,
		SignedData:        sd,
		EVMAddress:        addr,
	}, nil
}
```

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```
