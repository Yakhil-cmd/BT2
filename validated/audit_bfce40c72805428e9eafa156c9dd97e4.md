### Title
Cross-COA Signature Replay in `EVM.validateCOAOwnershipProof` - (File: fvm/evm/stdlib/contract.cdc)

### Summary

`EVM.validateCOAOwnershipProof` does not enforce that `signedData` encodes the target `evmAddress`. A signature produced to prove ownership of one COA (Cadence-Owned Account) can be replayed by any unprivileged caller to prove ownership of a different COA belonging to the same Cadence account, bypassing access controls in any on-chain protocol that relies on this function for authentication.

### Finding Description

`EVM.validateCOAOwnershipProof` verifies two things: (1) that the provided signatures are valid over `signedData` using the account's keys, and (2) that the COA resource at the given `path` in the account has an EVM address matching `evmAddress`. However, it never checks that `signedData` commits to `evmAddress`. [1](#0-0) 

The function signature accepts `signedData` and `evmAddress` as independent inputs: [2](#0-1) 

Signature verification is performed only over `signedData`, with no binding to `evmAddress`: [3](#0-2) 

The EVM address check is a separate, independent step that only verifies the COA resource at the given path matches the supplied `evmAddress`: [4](#0-3) 

The function is `access(all)` — callable by any Cadence script or transaction with arbitrary arguments.

### Impact Explanation

If a Cadence account controls two COAs (e.g., `COA_A` at `/public/coa` and `COA_B` at `/public/coa2`), a signature produced to prove ownership of `COA_A` over some `signedData` can be replayed by an attacker to prove ownership of `COA_B` by simply substituting `COA_B`'s EVM address and path. Because `signedData` is not bound to `evmAddress`, the signature verification step passes for both COAs.

Any on-chain protocol that calls `EVM.validateCOAOwnershipProof` to gate privileged operations — such as authorizing a bridge withdrawal, releasing escrowed assets, or granting elevated permissions — can be bypassed. An attacker who intercepts or observes a valid proof for one COA can replay it to impersonate ownership of a different COA belonging to the same account, potentially draining assets or gaining unauthorized access.

The COA's ERC-1271 `isValidSignature` implementation in `coa.sol` is not directly vulnerable because it hardcodes `address(this)` as the EVM address argument: [5](#0-4) 

However, the Cadence-level `EVM.validateCOAOwnershipProof` function is exposed as a public API and is the root cause.

### Likelihood Explanation

The attacker entry path is a standard unprivileged Cadence script or transaction calling `EVM.validateCOAOwnershipProof` with a replayed proof. The precondition — a Cadence account owning multiple COAs — is explicitly anticipated by the protocol (the code comment acknowledges it as a risk). As COA usage grows and multi-COA patterns become more common (e.g., one COA per dApp), the exploitability increases. Any protocol that builds authentication flows on top of `validateCOAOwnershipProof` without independently binding `signedData` to `evmAddress` is immediately vulnerable.

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` encodes `evmAddress` as a prefix or structured commitment before performing signature verification. For example:

```cadence
// Require that signedData begins with the 20-byte evmAddress
for i, b in evmAddress {
    if signedData[i] != b {
        return ValidationResult(isValid: false, problem: "signedData must commit to evmAddress")
    }
}
```

Alternatively, construct the message to be verified as `hash(evmAddress || signedData)` inside the function, removing the burden from callers. The current approach of delegating this responsibility to callers via a documentation comment is insufficient for a public, permissionless API.

### Proof of Concept

1. Account `X` owns `COA_A` at `/public/coa` (EVM address `0xAAAA...`) and `COA_B` at `/public/coa2` (EVM address `0xBBBB...`).
2. A legitimate protocol asks account `X` to prove ownership of `COA_A` by signing `signedData = bytes("authenticate")`. Account `X` produces a valid `COAOwnershipProof` with signatures over `signedData`.
3. An attacker observes this proof (e.g., from a public transaction or off-chain API call).
4. The attacker submits a Cadence script calling:
   ```cadence
   EVM.validateCOAOwnershipProof(
       address: X,
       path: /public/coa2,          // COA_B's path
       signedData: bytes("authenticate"),  // same signedData
       keyIndices: [0],
       signatures: [capturedSig],   // same signature
       evmAddress: 0xBBBB...        // COA_B's address
   )
   ```
5. Step 1 (signature check): passes — the signature is valid over `signedData` using account `X`'s key.
6. Step 2 (EVM address check): passes — the COA at `/public/coa2` has address `0xBBBB...`.
7. The function returns `isValid: true`, falsely proving ownership of `COA_B`. [1](#0-0) [6](#0-5)

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
