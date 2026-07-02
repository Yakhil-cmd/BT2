### Title
`validateCOAOwnershipProof` Does Not Bind Signatures to `CapabilityPath` or `evmAddress`, Enabling Cross-COA Signature Replay via ERC-1271 `isValidSignature` - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies Cadence account key signatures over an arbitrary `signedData` blob, but neither `CapabilityPath` nor `evmAddress` are included in the signed data. Because `CapabilityPath` is carried in the RLP-encoded `COAOwnershipProof` struct without being cryptographically bound to the signatures, an attacker who observes a valid proof for COA₁ can mutate the `CapabilityPath` field to point to COA₂ (a second COA owned by the same Cadence account) and replay the unchanged signatures. The ERC-1271 entry-point `isValidSignature` on COA₂ will then return `ValidERC1271Signature` for a message the account owner never authorized for COA₂.

---

### Finding Description

**Root cause — unsigned `CapabilityPath` in `COAOwnershipProof`**

`COAOwnershipProof` is defined in `fvm/evm/types/proof.go`:

```go
type COAOwnershipProof struct {
    KeyIndices     KeyIndices
    Address        FlowAddress
    CapabilityPath PublicPath   // ← NOT signed
    Signatures     Signatures
}
func (p *COAOwnershipProof) Encode() ([]byte, error) {
    return rlp.EncodeToBytes(p)
}
```

The struct is RLP-encoded and passed as the `_sig` argument to `isValidSignature`. The `CapabilityPath` field is part of the encoding but is **never included in the signed payload**.

**Validation logic in `validateCOAOwnershipProof`** (`fvm/evm/stdlib/contract.cdc`, lines 1082–1109):

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,          // ← only signedData is signed
    domainSeparationTag: "FLOW-V0.0-user"
)
// ...
if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
    // checks COA at `path` matches `evmAddress`
    ...
    return ValidationResult(isValid: true, problem: nil)
}
```

The function verifies signatures over `signedData` only, then independently checks that the COA resource at the caller-supplied `path` has the caller-supplied `evmAddress`. Neither `path` nor `evmAddress` is part of the signed commitment. The code comment at line 1003 explicitly acknowledges this:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."*

**EVM entry-point** (`fvm/evm/handler/coa/coa.sol`, lines 114–125):

```solidity
function isValidSignature(bytes32 _hash, bytes memory _sig)
    external view virtual returns (bytes4)
{
    (bool ok, bytes memory data) = cadenceArch.staticcall(
        abi.encodeWithSignature(
            "verifyCOAOwnershipProof(address,bytes32,bytes)",
            address(this), _hash, _sig   // address(this) = calling COA
        )
    );
    ...
}
```

`address(this)` is passed as `evmAddress`. The `_sig` blob (the RLP-encoded `COAOwnershipProof`) is fully attacker-controlled. The precompile decodes it via `DecodeABIEncodedProof` (`fvm/evm/precompiles/arch.go`, lines 219–243) and forwards `CapabilityPath` from the proof directly to `validateCOAOwnershipProof` without any integrity check.

**Exploit path (step-by-step)**

1. Alice owns a Cadence account with two COAs: COA₁ stored at `/public/coa1` and COA₂ stored at `/public/coa2`.
2. Alice legitimately signs `_hash` to authorize an action on COA₁. The resulting `COAOwnershipProof` has `CapabilityPath = "coa1"`. This proof is observable on-chain (e.g., in a transaction argument or event).
3. Attacker RLP-decodes the proof, replaces `CapabilityPath` with `"coa2"`, and RLP-re-encodes it. `Address`, `KeyIndices`, and `Signatures` are unchanged.
4. Attacker calls `isValidSignature(_hash, modifiedProof)` on COA₂'s EVM address.
5. The precompile invokes `validateCOAOwnershipProof(COA₂_evmAddr, "coa2", _hash, keyIndices, signatures, COA₂_evmAddr)`.
6. `keyList.verify(signedData: _hash, ...)` — **passes** (same signatures, same `_hash`).
7. `acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coa2)` — **passes** (Alice has COA₂ there).
8. COA₂'s EVM address matches `evmAddress` — **passes**.
9. `isValidSignature` returns `0x1626ba7e` (`ValidERC1271Signature`) for COA₂.

Any EVM smart contract that gates an asset transfer or privileged action on `isValidSignature` from COA₂ will now accept this forged authorization.

---

### Impact Explanation

An unprivileged attacker who observes a single valid COA ownership proof for COA₁ can replay it against COA₂ (owned by the same Cadence account) without possessing any private key. Any EVM protocol that relies on ERC-1271 `isValidSignature` for authorization — token approvals, NFT transfers, multisig thresholds, permit-style flows — will treat the forged proof as a genuine authorization from COA₂'s owner. This constitutes unauthorized movement of on-chain EVM assets held by or delegated to COA₂.

---

### Likelihood Explanation

Low-to-medium. The precondition is that the victim Cadence account holds **two or more COAs** at distinct public paths. The code comment acknowledges this is currently rare ("Flow wallets historically create at most one COA per account"), but the EVM ecosystem on Flow is growing and multi-COA setups are a natural pattern for users who want to separate DeFi and NFT activity. The attacker needs only to observe one on-chain proof (no private key material) and perform a trivial RLP field substitution. No front-running, staked node access, or privileged role is required.

---

### Recommendation

Enforce that `signedData` cryptographically commits to both `evmAddress` and `CapabilityPath` before the proof is accepted. Concretely, inside `validateCOAOwnershipProof`, verify that `signedData` is (or contains) a canonical encoding of `(evmAddress ‖ capabilityPath)`, or alternatively include those fields in the signed commitment at the proof-construction layer. The EVM-side `isValidSignature` wrapper should pass `address(this)` as part of the data the caller is expected to have signed, not merely as a runtime check after signature verification.

---

### Proof of Concept

```cadence
// Setup: Alice creates two COAs
transaction {
    prepare(alice: auth(Storage, Capabilities) &Account) {
        let coa1 <- EVM.createCadenceOwnedAccount()
        alice.storage.save(<-coa1, to: /storage/coa1)
        let cap1 = alice.capabilities.storage.issue<&EVM.CadenceOwnedAccount>(/storage/coa1)
        alice.capabilities.publish(cap1, at: /public/coa1)

        let coa2 <- EVM.createCadenceOwnedAccount()
        alice.storage.save(<-coa2, to: /storage/coa2)
        let cap2 = alice.capabilities.storage.issue<&EVM.CadenceOwnedAccount>(/storage/coa2)
        alice.capabilities.publish(cap2, at: /public/coa2)
    }
}
```

```
// Alice signs _hash for COA1 and publishes the proof on-chain.
// Attacker observes the RLP-encoded COAOwnershipProof{CapabilityPath:"coa1", ...}.
// Attacker decodes, sets CapabilityPath = "coa2", re-encodes.
// Attacker calls isValidSignature(_hash, modifiedProof) on COA2's EVM address.
// Result: 0x1626ba7e (ValidERC1271Signature) — COA2 appears to have signed _hash.
```

The root cause is confirmed at:
- `fvm/evm/stdlib/contract.cdc` lines 1082–1109 — signatures verified over `signedData` only; `path` and `evmAddress` are post-hoc checks, not part of the signed commitment.
- `fvm/evm/types/proof.go` lines 139–148 — `CapabilityPath` is RLP-encoded in the proof but never included in the signed data.
- `fvm/evm/handler/coa/coa.sol` lines 114–125 — `_sig` (the full mutable proof blob) is attacker-controlled; only `address(this)` is pinned by the EVM runtime. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1109)
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
```

**File:** fvm/evm/types/proof.go (L139-148)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}

func (p *COAOwnershipProof) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(p)
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
