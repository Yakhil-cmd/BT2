### Title
`validateCOAOwnershipProof` Lacks Nonce Binding to `evmAddress`, Enabling Cross-COA Signature Replay — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies Cadence account key signatures over an arbitrary `signedData` blob but does not enforce that `signedData` encodes the target COA's `evmAddress`. Because the signed payload carries no nonce and no COA-address binding, a signature produced for one COA is cryptographically valid for any other COA owned by the same Cadence account. There is no per-proof revocation mechanism; the only way to invalidate a captured signature is to revoke the entire account key, which breaks all transactions signed by that key.

---

### Finding Description

**Root cause — `validateCOAOwnershipProof`**

The function at `fvm/evm/stdlib/contract.cdc` lines 1001–1116 accepts five caller-supplied fields: `address`, `path`, `signedData`, `keyIndices`, and `signatures`. It performs two independent checks:

1. Verify that the supplied `signatures` are cryptographically valid over `signedData` with the account keys at `keyIndices`.
2. Borrow the COA resource at `path` and confirm its `.address().bytes` equals the `evmAddress` argument.

The two checks are never joined: `signedData` is never required to contain `evmAddress` or `path`. The code itself documents this gap:

> *"this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [1](#0-0) 

**How the EVM-side surface exposes this**

The COA smart-contract (`fvm/evm/handler/coa/coa.sol`) implements ERC-1271 `isValidSignature`:

```solidity
function isValidSignature(bytes32 _hash, bytes memory _sig)
    external view virtual returns (bytes4) {
    cadenceArch.staticcall(
        abi.encodeWithSignature(
            "verifyCOAOwnershipProof(address,bytes32,bytes)",
            address(this), _hash, _sig));
    ...
}
``` [2](#0-1) 

`address(this)` is the calling COA's EVM address; `_hash` becomes `signedData`; `_sig` is the RLP-encoded `COAOwnershipProof` (Cadence address + capability path + key indices + raw signatures).

`DecodeABIEncodedProof` in `fvm/evm/precompiles/arch.go` reconstructs the context:

```go
return types.NewCOAOwnershipProofInContext(hash, types.Address(caller), encodedProof)
``` [3](#0-2) 

The `COAOwnershipProof` embedded in `encodedProof` carries its own `Address` (Cadence account) and `CapabilityPath` — both attacker-controlled when the proof is submitted as `_sig`. [4](#0-3) 

**Exploit path (cross-COA replay)**

1. Alice holds two COAs under the same Cadence account: COA₁ at `/public/coa1`, COA₂ at `/public/coa2`.
2. Alice signs hash `H` to authorize an action on EVM contract A via COA₁. The `COAOwnershipProof` (Cadence address, `/public/coa1`, key indices, signatures-over-H) is broadcast on-chain.
3. Bob captures the proof. He constructs a new `COAOwnershipProof` identical except `CapabilityPath = /public/coa2`.
4. Bob calls `COA₂.isValidSignature(H, crafted_proof)`.
5. `validateCOAOwnershipProof` verifies the signatures over `H` — **valid**, because the signatures were produced over `H` with no COA-address binding.
6. It then borrows the resource at `/public/coa2` and confirms its EVM address equals `address(this)` (COA₂'s address) — **passes**, because the resource exists.
7. Returns `isValid: true` for COA₂, even though Alice never authorized anything for COA₂.

No nonce exists in `signedData`, so the replayed proof is valid indefinitely. Alice cannot selectively revoke it; revoking the account key at the used `keyIndex` would break all her Flow transactions. [5](#0-4) 

---

### Impact Explanation

An attacker who observes any on-chain COA ownership proof can replay it against any other COA owned by the same Cadence account. EVM contracts that rely on ERC-1271 (`isValidSignature`) for access control — e.g., multi-sig wallets, NFT marketplaces, DeFi protocols — would accept the forged authorization. This enables unauthorized asset transfers, contract calls, or privilege escalations on behalf of the victim's secondary COA. The victim has no targeted revocation path; revoking the signing key destroys all their transaction-signing capability.

**Impact: Medium** — requires the victim to hold multiple COAs, but the consequence is unauthorized on-chain asset control.

---

### Likelihood Explanation

The attacker needs only to:
- Observe a single valid COA ownership proof (available from any public transaction or EVM call that uses `isValidSignature`).
- Know that the victim's Cadence account has a second COA at a discoverable public capability path.

The protocol places no restriction on the number of COAs per account. As Flow EVM adoption grows and multi-COA patterns become common (e.g., one COA per dApp), the preconditions become increasingly easy to satisfy. No privileged access, no key material, and no staked-node control is required.

**Likelihood: Low-Medium** — currently constrained by the rarity of multi-COA accounts, but structurally reachable by any unprivileged observer.

---

### Recommendation

Enforce that `signedData` commits to the target COA's EVM address (and optionally the capability path) before signature verification. Concretely:

1. **Protocol-level enforcement**: Inside `validateCOAOwnershipProof`, derive an expected `signedData` prefix from `evmAddress` (and optionally `path`) and verify that the supplied `signedData` starts with or equals that prefix.
2. **Nonce support**: Add an optional nonce field to `COAOwnershipProof` and track consumed nonces per Cadence account, allowing users to invalidate specific proofs without revoking their keys.
3. **Documentation**: Until a protocol fix lands, prominently document in `isValidSignature` and `validateCOAOwnershipProof` that callers **must** encode `evmAddress` (and a nonce) inside `signedData` to prevent cross-COA replay.

---

### Proof of Concept

```
Alice's Cadence account: 0xALICE
  COA₁ at /public/coa1  →  EVM address 0xCOA1
  COA₂ at /public/coa2  →  EVM address 0xCOA2

Step 1 – Alice signs H for COA₁:
  proof₁ = COAOwnershipProof{
      Address:        0xALICE,
      CapabilityPath: "coa1",
      KeyIndices:     [0],
      Signatures:     [sig_over_H],   // sig_over_H = Sign(H, alice_key_0)
  }
  COA₁.isValidSignature(H, proof₁)  →  0x1626ba7e  ✓

Step 2 – Bob replays with COA₂ path (no key material needed):
  proof₂ = COAOwnershipProof{
      Address:        0xALICE,
      CapabilityPath: "coa2",         // ← changed
      KeyIndices:     [0],
      Signatures:     [sig_over_H],   // ← identical, still valid over H
  }
  COA₂.isValidSignature(H, proof₂)

Step 3 – validateCOAOwnershipProof:
  keyList.verify(signatureSet, signedData=H, ...)  →  true   (H was signed by alice_key_0)
  coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coa2)
  coaRef.address().bytes == 0xCOA2  →  true   (address(this) in isValidSignature)
  return ValidationResult(isValid: true)          ← unauthorized
```

The replay succeeds because `H` carries no binding to `0xCOA1` or `"coa1"`, and `validateCOAOwnershipProof` never checks that `signedData` encodes the target address. [6](#0-5) [2](#0-1) [7](#0-6) [8](#0-7)

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
