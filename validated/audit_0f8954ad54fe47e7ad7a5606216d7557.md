### Title
COA Ownership Proof Signature Has No Replay Protection — (`fvm/evm/stdlib/contract.cdc`)

### Summary
`EVM.validateCOAOwnershipProof` verifies Flow account key signatures over a caller-supplied `signedData` blob using the fixed domain tag `"FLOW-V0.0-user"`, but does not bind the signature to the specific EVM address being proven, any nonce, or any chain ID. The same `(signedData, signatures)` tuple is valid indefinitely, on any Flow network, and for any COA owned by the same Cadence account — a direct analog to the `enableModeSignature` replay described in the external report.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` (lines 1001–1116) accepts:

```
address: Address          // Flow account
path: PublicPath          // where the COA capability lives
signedData: [UInt8]       // arbitrary caller-controlled bytes
keyIndices: [UInt64]
signatures: [[UInt8]]
evmAddress: [UInt8; 20]
```

It verifies the signatures over `signedData` with the hardcoded domain tag `"FLOW-V0.0-user"`:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

The function itself acknowledges the gap in its own NatSpec comment:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."*

Three independent replay vectors exist:

**1. Indefinite same-context replay.** There is no nonce, sequence number, or expiry. Once a valid `(signedData, signatures)` pair appears on-chain (e.g., in a transaction that called the EVM precompile or `validateCOAOwnershipProof` directly), any observer can extract it and replay it in a new transaction or EVM call. If a protocol uses ERC-1271 (`isValidSignature`) via the COA contract for one-time authorization (governance vote, withdrawal approval, etc.), the same proof authorizes the same action again.

**2. Cross-chain replay.** `signedData` contains no chain ID. A proof signed on Flow Testnet is cryptographically valid on Flow Mainnet for the same account/key pair. An attacker who observes a testnet proof can replay it on mainnet.

**3. Cross-purpose replay.** Any signature produced with the `"FLOW-V0.0-user"` tag over any 32-byte value — for any application — is a valid COA ownership proof for that same 32-byte value. A user who signs a message for a web2 login, a different dApp, or any other `"FLOW-V0.0-user"`-tagged purpose inadvertently produces a reusable COA ownership proof.

The EVM-side entry point is the `verifyCOAOwnershipProof(address,bytes32,bytes)` precompile in `fvm/evm/precompiles/arch.go` (`DecodeABIEncodedProof`, lines 219–243), which decodes the ABI-encoded call and forwards it to `coaOwnershipProofValidator` in `fvm/evm/handler/precompiles.go` (lines 115–153), which invokes `EVM.validateCOAOwnershipProof`. The COA's ERC-1271 implementation in `fvm/evm/handler/coa/coa.sol` (lines 114–125) calls this precompile with `address(this)` as the EVM address and the caller-supplied `_hash` as `signedData`.

### Impact Explanation

Any EVM contract that relies on ERC-1271 via a COA (e.g., for governance, multi-sig, or access control) is vulnerable to replay of previously observed proofs. An unprivileged attacker who can read on-chain transaction data can:

- Re-authorize a previously authorized action (double-vote, double-spend, repeated withdrawal approval).
- Use a proof signed on a test network to authorize actions on mainnet.
- Use a signature produced for an unrelated application to pass COA ownership checks.

The impact is unauthorized state changes or asset movement in any protocol that uses COA ERC-1271 without implementing its own proof-tracking.

### Likelihood Explanation

All submitted proofs are visible in on-chain transaction calldata. Any observer can extract a valid `(signedData, signatures)` pair and replay it. No privileged access is required. The attacker entry point is a standard EVM transaction calling the Cadence Arch precompile, or a Cadence script/transaction calling `EVM.validateCOAOwnershipProof` directly (the function is `access(all)`).

### Recommendation

Bind the COA ownership proof signature to the specific context in which it is used. The minimal fix is to require that `signedData` commits to the `evmAddress`, the Flow `address`, and a chain-specific value (e.g., the Flow chain ID or a block hash). A stronger fix adds a nonce or expiry to prevent indefinite replay:

```cadence
// Enforce that signedData encodes evmAddress at minimum
pre {
    signedData.length >= 20:
        "signedData must include the evmAddress to prevent cross-address replay"
    // Optionally: verify signedData[0..<20] == evmAddress
}
```

For full protection, the signed message should be a structured hash that includes: `chainID || evmAddress || flowAddress || nonce || expiry || applicationData`.

### Proof of Concept

1. Account `A` on Flow Testnet owns a COA at `/public/coa`.
2. A DeFi protocol on Flow EVM Testnet calls `isValidSignature(hash, proof)` on the COA to authorize a governance vote. The COA's `isValidSignature` calls `verifyCOAOwnershipProof(address(this), hash, proof)`. The proof is accepted and the vote is recorded.
3. The same account `A` exists on Flow Mainnet with the same keys.
4. An attacker extracts `(hash, proof)` from the Testnet transaction calldata.
5. The attacker submits an EVM transaction on Mainnet calling `verifyCOAOwnershipProof(coaAddressOnMainnet, hash, proof)`. The Cadence function verifies the signatures over `hash` with tag `"FLOW-V0.0-user"` — the same keys, the same hash, the same signatures — and returns `isValid: true`.
6. The attacker has successfully replayed a Testnet authorization on Mainnet, or replayed the same authorization a second time on the same network.

**Relevant code locations:**

- `fvm/evm/stdlib/contract.cdc` lines 1001–1116 — `validateCOAOwnershipProof` (missing replay protection, acknowledged in comment) [1](#0-0) 
- `fvm/evm/stdlib/contract.cdc` lines 1082–1086 — signature verification with fixed tag, no nonce/chain binding [2](#0-1) 
- `fvm/evm/precompiles/arch.go` lines 219–243 — `DecodeABIEncodedProof`, the EVM-reachable entry point [3](#0-2) 
- `fvm/evm/handler/coa/coa.sol` lines 114–125 — ERC-1271 `isValidSignature` calling the precompile [4](#0-3) 
- `fvm/evm/types/proof.go` lines 95–118 — `COAOwnershipProofInContext` struct, `signedData` is opaque bytes with no context binding [5](#0-4)

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

**File:** fvm/evm/types/proof.go (L95-118)
```go
// COAOwnershipProofInContext contains all the data
// needed to verify a COAOwnership proof.
// The proof is verified by checking the signatures over the
// input signed data (SignedData), then loading the resource
// capability from the provided path in the proof, and
// at last checking if the EVMAddress of the resource matches
// the provided one.
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
