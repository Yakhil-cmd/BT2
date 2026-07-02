### Title
COA Contract Fails to Declare ERC-1271 Support via ERC-165 `supportsInterface` — (`File: fvm/evm/handler/coa/coa.sol`)

### Summary

The `COA` contract in `fvm/evm/handler/coa/coa.sol` implements `isValidSignature` (ERC-1271) and is explicitly documented as supporting ERC-1271, but its `supportsInterface` function does not include the ERC-1271 interface ID (`0x1626ba7e`). Any EVM contract or tool that performs ERC-165 introspection before invoking ERC-1271 signature validation will incorrectly conclude that COAs do not support ERC-1271, causing COA-based signature flows to silently fail or be rejected.

### Finding Description

The `COA` contract declares itself as implementing `IERC165` and correctly reports support for `ERC1155TokenReceiver`, `ERC721TokenReceiver`, `ERC777TokensRecipient`, and `IERC165` itself. It also implements `isValidSignature(bytes32,bytes)` (ERC-1271) and even defines the magic value constant `ValidERC1271Signature = 0x1626ba7e`.

However, the `supportsInterface` function omits ERC-1271:

```solidity
// fvm/evm/handler/coa/coa.sol lines 67-73
function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId;
    // 0x1626ba7e (ERC-1271) is NOT included
}
```

The official Flow documentation in `contract.cdc` explicitly states:

> "COAs are smart contract wallets that accept native token transfers and support several ERCs including ERC-165, ERC-721, ERC-777, ERC-1155, **ERC-1271**."

This is a direct standard non-compliance: the contract implements ERC-1271 but does not advertise it through the ERC-165 introspection mechanism it already provides.

### Impact Explanation

ERC-1271-aware EVM protocols (e.g., OpenSea's Seaport, Gnosis Safe integrations, EIP-712 permit flows, governance contracts) routinely call `supportsInterface(0x1626ba7e)` before invoking `isValidSignature`. When called on a COA, this returns `false`, causing those protocols to:

1. Reject COA-based signature validation entirely, even though `isValidSignature` is present and functional.
2. Fall back to ECDSA/EOA verification, which COAs cannot satisfy (COAs have no private key).
3. Silently block COA users from participating in ERC-1271-gated actions (token approvals, off-chain order signing, governance votes, etc.).

Because COAs are the primary mechanism for Cadence accounts to interact with Flow EVM, this non-compliance degrades the usability and interoperability of the entire COA system with the broader EVM ecosystem.

### Likelihood Explanation

The entry path is trivially reachable: any EVM transaction or script calling `supportsInterface(0x1626ba7e)` on a COA address triggers the incorrect `false` return. No special privileges are required. Any third-party EVM contract that follows the standard best practice of checking ERC-165 before calling `isValidSignature` will be affected. This is a common pattern in production DeFi and NFT protocols.

### Recommendation

Add ERC-1271 interface ID to the `supportsInterface` function in `coa.sol`:

```solidity
bytes4 constant internal ERC1271InterfaceId = 0x1626ba7e;

function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId ||
        id == ERC1271InterfaceId;  // add ERC-1271 support
}
```

### Proof of Concept

1. The COA contract implements `isValidSignature` at lines 114–125 and defines `ValidERC1271Signature = 0x1626ba7e`.
2. The `supportsInterface` function at lines 67–73 does not include `0x1626ba7e`.
3. `contract.cdc` line 474 explicitly documents ERC-1271 as a supported standard.
4. Any EVM call `COA.supportsInterface(0x1626ba7e)` returns `false`.
5. ERC-1271-aware protocols that guard `isValidSignature` calls behind an ERC-165 check will reject COA signatures.

**Root cause:** [1](#0-0) 

**ERC-1271 implementation present but not declared:** [2](#0-1) 

**ERC-1271 implementation body:** [3](#0-2) 

**Documentation claiming ERC-1271 support:** [4](#0-3)

### Citations

**File:** fvm/evm/handler/coa/coa.sol (L61-63)
```text
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 constant internal ValidERC1271Signature = 0x1626ba7e;
    bytes4 constant internal InvalidERC1271Signature = 0xffffffff;
```

**File:** fvm/evm/handler/coa/coa.sol (L67-73)
```text
    function supportsInterface(bytes4 id) external view virtual override returns (bool) {
        return
            id == type(ERC1155TokenReceiver).interfaceId ||
            id == type(ERC721TokenReceiver).interfaceId ||
            id == type(ERC777TokensRecipient).interfaceId ||
            id == type(IERC165).interfaceId;
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

**File:** fvm/evm/stdlib/contract.cdc (L472-474)
```text
        From the EVM perspective, COAs are smart contract wallets
        that accept native token transfers and support several ERCs
        including ERC-165, ERC-721, ERC-777, ERC-1155, ERC-1271.
```
