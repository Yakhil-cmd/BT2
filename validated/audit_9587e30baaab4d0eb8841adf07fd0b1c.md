### Title
`validateCOAOwnershipProof` Signed Payload Lacks Domain Binding, Enabling Cross-Chain and Cross-COA Replay - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence account key signatures over a caller-supplied `signedData` blob using the fixed domain tag `"FLOW-V0.0-user"`. Neither the target EVM address (`evmAddress`) nor the Flow chain ID is committed to inside the signed payload. Because the same domain tag and the same key material exist on every Flow network, a signature produced on one network (or for one COA) is cryptographically valid on any other network (or for any other COA owned by the same account). This is the direct Flow analog of the Revolver `joinGame` finding: a signed payload that omits session/deployment binding.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs the following verification:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,          // ← only this is signed
    domainSeparationTag: "FLOW-V0.0-user"
)
``` [1](#0-0) 

The `signedData` is an opaque caller-supplied byte array. The function then separately checks that the `evmAddress` argument matches the COA resource stored at `path`:

```cadence
if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
    let coaAddressBytes = coaRef.address().bytes
    for index, item in coaAddressBytes {
        if item != evmAddress[index] { ... }
    }
``` [2](#0-1) 

The `evmAddress` is verified **after** signature validation, but it is **not part of the signed message**. The signed payload commits only to `signedData` (the raw bytes supplied by the caller). Neither the COA's EVM address nor the Flow chain ID is included in what is actually signed.

The code itself acknowledges this gap:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [3](#0-2) 

The EVM-side entry point is the COA's ERC-1271 `isValidSignature` in `coa.sol`, which calls the Cadence Arch precompile with `address(this)` as the EVM address:

```solidity
cadenceArch.staticcall(abi.encodeWithSignature(
    "verifyCOAOwnershipProof(address,bytes32,bytes)",
    address(this), _hash, _sig
));
``` [4](#0-3) 

`DecodeABIEncodedProof` in the precompile layer decodes the caller-supplied `address` and `hash` and passes them directly to `validateCOAOwnershipProof` without any chain-binding:

```go
return types.NewCOAOwnershipProofInContext(
    hash,
    types.Address(caller),
    encodedProof,
)
``` [5](#0-4) 

The domain tag `"FLOW-V0.0-user"` is a fixed string with no chain component. Flow mainnet, testnet, and every other network all use the same tag.

### Impact Explanation

`validateCOAOwnershipProof` is the backbone of ERC-1271 signature verification for all COA contracts on Flow EVM. ERC-1271 is used by DeFi protocols (DEX order books, permit-based approvals, NFT marketplaces, bridge authorizations) to verify that a smart-contract wallet has authorized a specific action.

**Cross-chain replay**: A user who signs `signedData = H` on Flow testnet (e.g., to authorize a small test trade) produces a signature that is cryptographically valid on Flow mainnet for the same `H`. If the same Flow account exists on mainnet with the same key and a COA, an attacker can replay the testnet signature on mainnet by calling `isValidSignature(H, proof)` against the mainnet COA. The `evmAddress` check passes because the attacker supplies the correct mainnet COA address (which is public on-chain), and the signature check passes because the signed data `H` is identical and the domain tag is identical.

**Cross-COA replay (same chain)**: If a Cadence account owns multiple COAs (stored at different capability paths), a signature produced for one COA is valid for any other COA owned by the same account, because the EVM address is not in the signed payload.

Concrete impact: unauthorized ERC-1271 approvals on behalf of a user — e.g., a DEX order signed on testnet replayed on mainnet, or a permit signed for one COA replayed for a higher-value COA on the same account.

### Likelihood Explanation

- The attacker entry path is fully unprivileged: any EVM transaction can call `isValidSignature` on a COA contract, which triggers the precompile, which calls `validateCOAOwnershipProof`.
- Cross-chain replay requires the victim to have the same Flow account key on both testnet and mainnet (common for developers and power users) and to have signed any `bytes32` value on testnet that the attacker can reuse on mainnet.
- Cross-COA replay on the same chain requires only that the victim owns more than one COA — a scenario the code comment itself identifies as realistic.
- No privileged access, no leaked keys, no staked-node compromise is needed.

### Recommendation

Bind the signed payload to the EVM address and the chain ID. The simplest fix is to enforce inside `validateCOAOwnershipProof` that `signedData` encodes both the `evmAddress` and the chain ID, or to construct the message to be verified as:

```cadence
let boundMessage: [UInt8] = chainID.utf8
    .concat(evmAddress.bytes)
    .concat(signedData)

let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: boundMessage,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

Alternatively, adopt a structured approach (analogous to EIP-712) where the domain includes the chain ID and the COA EVM address, so signatures are unambiguously scoped to a single deployment and a single COA.

### Proof of Concept

1. **Setup**: Alice has the same Flow account key on testnet and mainnet. On testnet she has a COA at `/public/coa` with EVM address `0xTEST`. On mainnet she has a COA at `/public/coa` with EVM address `0xMAIN`.

2. **Obtain testnet signature**: Alice signs `H = keccak256("authorize_order_1_USDC")` on testnet using her Flow key with tag `"FLOW-V0.0-user"`. She submits this to a testnet DEX as an ERC-1271 proof. The proof struct contains `{Address: alice_flow_addr, CapabilityPath: "coa", KeyIndices: [0], Signatures: [sig]}`.

3. **Replay on mainnet**: Attacker constructs an EVM transaction on mainnet calling `mainnetCOA.isValidSignature(H, encodedProof)`. The COA calls `verifyCOAOwnershipProof(0xMAIN, H, encodedProof)`. `DecodeABIEncodedProof` sets `EVMAddress = 0xMAIN` and `SignedData = H`. `validateCOAOwnershipProof` verifies `sig` over `H` with tag `"FLOW-V0.0-user"` — this passes because the key and tag are identical to testnet. The `evmAddress` check passes because `0xMAIN` is Alice's actual mainnet COA address. The function returns `isValid: true`.

4. **Result**: The mainnet DEX (or any ERC-1271 consumer) accepts the replayed testnet signature as a valid mainnet authorization, enabling the attacker to act on Alice's behalf on mainnet using only a signature she produced on testnet.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1003-1009)
```text
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

**File:** fvm/evm/stdlib/contract.cdc (L1095-1105)
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
```

**File:** fvm/evm/handler/coa/coa.sol (L118-118)
```text
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
```

**File:** fvm/evm/precompiles/arch.go (L238-242)
```go
	return types.NewCOAOwnershipProofInContext(
		hash,
		types.Address(caller),
		encodedProof,
	)
```
