### Title
COA Ownership Proof Signature Replay Across Multiple COAs of the Same Cadence Account — (`fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence account key signatures over an arbitrary `signedData` blob, but does not enforce that `signedData` encodes the target `evmAddress` or `CapabilityPath`. Because the `COAOwnershipProof` struct carries `CapabilityPath` as unsigned metadata, an attacker who captures a valid proof for COA-A can mutate the `CapabilityPath` field and replay the unchanged signatures to pass ownership validation for COA-B — a different COA owned by the same Cadence account.

---

### Finding Description

`validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` accepts six parameters: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`. It verifies that the Cadence account's keys produced valid signatures over `signedData`, then separately checks that the COA resource stored at `path` has the expected `evmAddress`. [1](#0-0) 

The code itself documents the gap:

> "this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [2](#0-1) 

The on-wire proof structure (`COAOwnershipProof`) carries `CapabilityPath` as an unsigned field alongside the signatures: [3](#0-2) 

`CapabilityPath` is never included in `signedData`; it is only used after signature verification to borrow the COA resource and compare its EVM address. An attacker can therefore take a proof produced for COA-A, replace `CapabilityPath` with the path of COA-B (owned by the same Cadence account), and present it as a valid proof for COA-B.

The EVM-side entry point is the ERC-1271 `isValidSignature` function in the COA Solidity contract, which calls the `verifyCOAOwnershipProof` precompile with `address(this)` as the EVM address: [4](#0-3) 

The precompile decodes the ABI-encoded call, reconstructing a `COAOwnershipProofInContext` where `EVMAddress` comes from the EVM caller (`address(this)`) and `SignedData` comes from `_hash`, while the `CapabilityPath` comes from the attacker-supplied `_sig` blob: [5](#0-4) 

Because `CapabilityPath` is not signed, the attacker can freely substitute it.

---

### Impact Explanation

A Cadence account that owns two COAs (COA-A at `/public/coaA`, COA-B at `/public/coaB`) is vulnerable. Any signature the account's keys produce over an arbitrary hash `D` — for example, to authorize an ERC-1271 check on COA-A — can be replayed against COA-B by an attacker who:

1. Captures the encoded `COAOwnershipProof` (which is public, passed as calldata).
2. Decodes it, replaces `CapabilityPath` with `/public/coaB`, re-encodes it.
3. Calls `COA-B.isValidSignature(D, modified_proof)`.

The `validateCOAOwnershipProof` call succeeds: the signatures are still valid over `D`, and the COA at `/public/coaB` does have the expected EVM address. COA-B therefore appears to have authorized whatever `D` represents, even though the account owner only intended to authorize it for COA-A.

This enables unauthorized ERC-1271 signature validation on COA-B, which can be exploited in any EVM protocol that relies on `isValidSignature` for access control (e.g., ERC-4337 paymasters, NFT marketplace approvals, multisig wallets).

---

### Likelihood Explanation

The likelihood is **Low**:

- It requires the victim Cadence account to own at least two COAs, which is uncommon today (the comment notes "Flow wallets historically create at most one COA per account").
- The attacker must observe a valid proof in flight (e.g., from a prior EVM transaction's calldata).
- No privileged access is required; the attack is fully executable by an unprivileged EVM transaction sender.

---

### Recommendation

Enforce that `signedData` commits to the specific COA being proven. The simplest fix is to require callers to include the `evmAddress` bytes inside `signedData` before signing, and add an on-chain check inside `validateCOAOwnershipProof` that asserts `signedData` contains the expected `evmAddress`. Alternatively, include `CapabilityPath` in the signed payload so that a proof for one path cannot be repurposed for another.

---

### Proof of Concept

**Setup:** Cadence account `0xABCD` owns two COAs:
- COA-A at `/public/coaA` with EVM address `0xAAAA...`
- COA-B at `/public/coaB` with EVM address `0xBBBB...`

**Step 1 — Legitimate proof for COA-A:**
Account `0xABCD` signs hash `D` and submits a transaction that calls `COA-A.isValidSignature(D, proof_A)` where `proof_A` encodes `{Address: 0xABCD, CapabilityPath: "coaA", Signatures: [...], KeyIndices: [...]}`.

**Step 2 — Attacker captures `proof_A` from calldata.**

**Step 3 — Attacker constructs `proof_B`:**
Decode `proof_A`, set `CapabilityPath = "coaB"`, re-RLP-encode → `proof_B`.

**Step 4 — Attacker calls `COA-B.isValidSignature(D, proof_B)`:**
- `verifyCOAOwnershipProof(0xBBBB..., D, proof_B)` is invoked.
- `validateCOAOwnershipProof(address: 0xABCD, path: /public/coaB, signedData: D, ..., evmAddress: 0xBBBB...)` runs.
- Signature check: `0xABCD`'s keys signed `D` → **passes**.
- COA check: COA at `/public/coaB` has address `0xBBBB...` → **passes**.
- Returns `ValidationResult(isValid: true)`.

COA-B now appears to have authorized `D`, despite the account owner never intending this. [6](#0-5) [7](#0-6)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1001-1018)
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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1110)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )

        if !isValid{
            return ValidationResult(
                isValid: false,
                problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership for Cadence account \(address). The given signatures are not valid or provide enough weight."
            )
        }

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

**File:** fvm/evm/handler/coa/coa.sol (L114-125)
```text
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

**File:** fvm/evm/precompiles/arch.go (L219-243)
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
}
```
