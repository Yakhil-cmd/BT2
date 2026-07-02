### Title
COA ERC165 `supportsInterface()` Does Not Declare ERC1271 Support — (`File: fvm/evm/handler/coa/coa.sol`)

---

### Summary

The Flow EVM Cadence-Owned Account (COA) contract implements ERC1271 (`isValidSignature`) but omits the ERC1271 interface ID from its `supportsInterface()` declaration. Any EVM client or on-chain contract that correctly guards ERC1271 calls with an ERC165 check will conclude the COA does not support signature validation and refuse to interact with it as a signer.

---

### Finding Description

The COA contract at `fvm/evm/handler/coa/coa.sol` implements `IERC165` and declares support for `ERC1155TokenReceiver`, `ERC721TokenReceiver`, `ERC777TokensRecipient`, and `IERC165` itself:

```solidity
function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId;
}
``` [1](#0-0) 

The same contract also implements ERC1271 via `isValidSignature`:

```solidity
// ERC1271 requirement
function isValidSignature(
    bytes32 _hash,
    bytes memory _sig
) external view virtual returns (bytes4) { ... }
``` [2](#0-1) 

The ERC1271 interface ID is `bytes4(keccak256("isValidSignature(bytes32,bytes)"))` = `0x1626ba7e`, which is already defined as the constant `ValidERC1271Signature` in the same file:

```solidity
// bytes4(keccak256("isValidSignature(bytes32,bytes)")
bytes4 constant internal ValidERC1271Signature = 0x1626ba7e;
``` [3](#0-2) 

The EVM contract documentation in `contract.cdc` explicitly lists ERC-1271 as a supported standard for COAs:

> "COAs are smart contract wallets that accept native token transfers and support several ERCs including ERC-165, ERC-721, ERC-777, ERC-1155, **ERC-1271**." [4](#0-3) 

Despite this, `supportsInterface(0x1626ba7e)` returns `false` on every COA.

---

### Impact Explanation

ERC1271 is the standard for smart contract signature validation. Protocols that use COAs as signers — including ERC-4337 account abstraction bundlers, Safe multisig, OpenSea, and any on-chain contract that guards `isValidSignature` calls with a prior `supportsInterface(0x1626ba7e)` check — will receive `false` and reject the COA as a valid signer. This silently breaks COA-based authentication and signing flows for any ERC165-compliant client, causing cross-VM asset loss or authorization failures for users who rely on COA ownership proofs in EVM-side protocols.

---

### Likelihood Explanation

The ERC1271 standard is widely used in EVM DeFi and NFT protocols. Any EVM contract or off-chain client that follows the ERC165 discovery pattern before invoking `isValidSignature` will be affected. The entry path is fully unprivileged: any EVM transaction sender can call `supportsInterface(0x1626ba7e)` on a COA address and observe the incorrect `false` return. No special access or keys are required.

---

### Recommendation

Add the ERC1271 interface ID to `supportsInterface()` in `fvm/evm/handler/coa/coa.sol`:

```solidity
function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId ||
        id == ValidERC1271Signature; // ERC1271: bytes4(keccak256("isValidSignature(bytes32,bytes)"))
}
```

The constant `ValidERC1271Signature = 0x1626ba7e` is already defined in the contract and equals the ERC1271 interface ID, so no new constant is needed.

---

### Proof of Concept

1. Deploy any ERC165-checking contract on Flow EVM:
   ```solidity
   interface IERC165 { function supportsInterface(bytes4) external view returns (bool); }
   interface IERC1271 { function isValidSignature(bytes32, bytes memory) external view returns (bytes4); }

   contract Checker {
       function checkCOA(address coa) external view returns (bool supportsERC1271) {
           // ERC165 check before calling isValidSignature — standard pattern
           supportsERC1271 = IERC165(coa).supportsInterface(0x1626ba7e);
       }
   }
   ```
2. Call `checkCOA(<any COA address>)` — returns `false`.
3. Call `IERC1271(<same COA address>).isValidSignature(hash, proof)` directly — returns `0x1626ba7e` (valid) when a correct COA ownership proof is supplied.
4. The discrepancy confirms: the COA implements ERC1271 but does not advertise it, causing any ERC165-compliant client to incorrectly reject the COA as an ERC1271 signer. [5](#0-4)

### Citations

**File:** fvm/evm/handler/coa/coa.sol (L49-73)
```text
contract COA is ERC1155TokenReceiver, ERC777TokensRecipient, ERC721TokenReceiver, IERC165 {
    address constant public cadenceArch = 0x0000000000000000000000010000000000000001;

    // bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))
    bytes4 constant internal ERC721ReceivedIsSupported = 0x150b7a02;

    // bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))
    bytes4 constant internal ERC1155ReceivedIsSupported = 0xf23a6e61;

    // bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))
    bytes4 constant internal ERC1155BatchReceivedIsSupported = 0xbc197c81;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 constant internal ValidERC1271Signature = 0x1626ba7e;
    bytes4 constant internal InvalidERC1271Signature = 0xffffffff;

    receive() external payable  {
    }
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
