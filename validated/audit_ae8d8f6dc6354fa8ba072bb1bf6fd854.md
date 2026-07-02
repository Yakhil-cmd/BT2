### Title
COA Ownership Proof Signatures Not Bound to EVM Address — Cross-COA Replay Attack - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` verifies that a set of Cadence account key signatures are valid over caller-supplied `signedData`, then checks that the COA at the given `path` matches the supplied `evmAddress`. Because the function does not enforce that `signedData` encodes `evmAddress`, a signature produced for one COA owned by a Cadence account is cryptographically valid for any other COA owned by the same account. An unprivileged attacker who observes a legitimate signature for COA_A can replay it to forge a passing ownership proof for COA_B on the same Cadence account.

### Finding Description

`validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` accepts six caller-controlled parameters: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`. [1](#0-0) 

The function verifies the signatures over `signedData` using the Cadence account's keys: [2](#0-1) 

It then checks that the COA resource at `path` has the address matching `evmAddress`: [3](#0-2) 

The code itself acknowledges the root cause in a comment: [4](#0-3) 

Because `signedData` is arbitrary bytes with no enforced structure, a signature `sig = Sign(signedData, key_of_account_A)` is equally valid whether the verifier checks it against COA_A or COA_B — both are owned by the same Cadence account and share the same keys. The attacker controls `path` and `evmAddress` in the call, so they can substitute COA_B's path and address while reusing the signature originally produced for COA_A.

The function is `access(all)` and is callable from any Cadence script or transaction without privilege. The `COAOwnershipProof` struct embedded in the proof does not include the target EVM address: [5](#0-4) 

The signed data field is a free-form byte array with no protocol-enforced binding to any COA address: [6](#0-5) 

### Impact Explanation

The function is the on-chain primitive for ERC-1271 smart contract signature validation for COA wallets. The COA Solidity contract's `isValidSignature` calls the precompile `verifyCOAOwnershipProof(address(this), _hash, _sig)`, which always passes the calling contract's own address — so that specific path is safe. [7](#0-6) 

However, `EVM.validateCOAOwnershipProof` is also directly callable from any Cadence script or transaction. Any dApp or protocol that calls it directly for authentication or authorization (e.g., off-chain login, on-chain access control, bridge authorization) is vulnerable. If a Cadence account holds two COAs at different paths — which the protocol permits and does not restrict — an attacker who has observed a valid signature for COA_A can replay it to forge a passing proof for COA_B. This constitutes unauthorized impersonation of a COA identity, which can lead to unauthorized asset transfers or approvals in any system that trusts the proof result.

### Likelihood Explanation

The preconditions are:
1. A Cadence account holds more than one COA (permitted by the protocol; not enforced to be one).
2. A valid signature over some `signedData` for that account is observable by the attacker (e.g., from a prior on-chain authentication event or public transaction).
3. A dApp or protocol calls `EVM.validateCOAOwnershipProof` directly rather than exclusively through the EVM precompile.

Condition 3 is the limiting factor today, but the function is `access(all)` and is the documented Cadence-side API for COA ownership verification. As multi-COA usage and direct Cadence-side integrations grow, the likelihood increases. The attacker needs no privileged access.

### Recommendation

Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof` itself, rather than relying on callers to do so. Concretely, the function should hash or prefix `signedData` with `evmAddress` before passing it to `keyList.verify`, or it should reject calls where `signedData` does not contain the expected EVM address bytes. This mirrors the fix recommended in the external report: include the target address in the signed payload so the signature is cryptographically bound to a specific COA.

### Proof of Concept

1. Cadence account `0xALICE` holds two COAs: COA_A at `/public/coaA` (EVM address `0xAAAA...`) and COA_B at `/public/coaB` (EVM address `0xBBBB...`).
2. Alice signs `signedData = "authenticate"` with her Cadence key (index 0) for a dApp that calls `EVM.validateCOAOwnershipProof` to verify ownership of COA_A. The signature `sig` is recorded on-chain or observed by the attacker.
3. The attacker calls `EVM.validateCOAOwnershipProof(address: 0xALICE, path: /public/coaB, signedData: "authenticate", keyIndices: [0], signatures: [sig], evmAddress: 0xBBBB...)` from any Cadence script.
4. `keyList.verify` passes — the signature is valid over `"authenticate"` under Alice's key, regardless of which COA is the target.
5. The COA address check passes — COA_B at `/public/coaB` has address `0xBBBB...`, which matches the attacker-supplied `evmAddress`.
6. The function returns `ValidationResult(isValid: true)`, falsely asserting that Alice authorized COA_B for this signed data, when she only authorized COA_A. [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1116)
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

        return ValidationResult(
            isValid: false,
            problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. Could not borrow the COA resource for account \(address)."
        )
    }
```

**File:** fvm/evm/types/proof.go (L102-106)
```go
type COAOwnershipProofInContext struct {
	COAOwnershipProof
	SignedData SignedData
	EVMAddress Address
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
