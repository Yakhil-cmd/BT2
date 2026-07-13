### Title
Unguarded Inherited `burn(address, uint)` on `ModuleCRC21` and `ModuleCRC20` Allows Unauthorized Token Destruction Bypassing Bridge/IBC Accounting — (File: `contracts/src/ModuleCRC21.sol`, `contracts/src/ModuleCRC20.sol`)

---

### Summary

`ModuleCRC21` and `ModuleCRC20` both inherit from `DSToken` but do not override its public `burn(address guy, uint wad)` (the direct analog of `burnFrom()`) or `burn(uint wad)` functions. Any unprivileged user can call these inherited functions to destroy CRC20/CRC21 tokens without emitting the bridge/IBC hook events that the Cronos module requires to release or reconcile the corresponding native assets. For non-source (IBC voucher) tokens this permanently locks the counterpart native tokens in the IBC escrow account; for source tokens it permanently destroys them with no corresponding native-side action.

---

### Finding Description

`ModuleCRC21` (and the older `ModuleCRC20`) inherit from `DSToken`:

```solidity
contract ModuleCRC21 is DSToken { ... }
```

`DSToken` exposes two public burn entry points that are **not overridden** in either contract:

| Selector | Behaviour |
|---|---|
| `burn(uint wad)` | Burns `wad` from `msg.sender` — no approval required |
| `burn(address guy, uint wad)` | Burns `wad` from `guy` if `allowance[guy][msg.sender] >= wad` — the direct `burnFrom()` analog |

Both appear verbatim in the deployed ABI (`ModuleCRC21.json`, `ModuleCRC20.json`).

The contracts define their own controlled burn paths (`send_to_ibc`, `send_to_evm_chain`, `send_to_ethereum`) that call the private/internal `unsafe_burn` **and** emit the hook events (`__CronosSendToIbc`, `__CronosSendToEvmChain`, `__CronosSendToEthereum`) that the Cronos EVM hook layer listens to in order to release or escrow the corresponding native assets. Calling the inherited `burn` functions skips those events entirely. [1](#0-0) [2](#0-1) [3](#0-2) 

The ABI confirms both `burn` overloads are publicly reachable on the deployed contract: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

**Non-source tokens (IBC vouchers):** When a CRC21 token represents an IBC voucher, the correct redemption path is `send_to_ibc` → `unsafe_burn` + `__CronosSendToIbc` event → Cronos module releases the escrowed native tokens on the source chain. Calling `burn(amount)` or `burn(victim, amount)` destroys the CRC21 token with no event, so the native tokens remain permanently locked in the IBC escrow account. This is an irreversible accounting divergence between the EVM token supply and the IBC escrow balance.

**Source tokens:** Burning CRC21 tokens directly destroys them without triggering the `mint_by_cronos_module` / `transfer_from_cronos_module` reverse path, permanently destroying the EVM-side representation with no corresponding native-side action.

**`burn(address guy, uint wad)` specifically:** A user who has been granted an ERC-20 allowance (e.g., for a DEX or lending protocol) can have their CRC21 tokens burned by the approved spender without their consent and without any bridge/IBC credit — a direct analog to the reported `burnFrom()` issue. [6](#0-5) 

---

### Likelihood Explanation

The entry point is a standard public ERC-20-style function callable by any EOA or contract with no preconditions beyond holding (or being approved for) a token balance. No privileged key, governance action, or special setup is required. Any holder of CRC21 tokens can self-burn; any address with an allowance can burn on behalf of the approver.

---

### Recommendation

Override both `burn` overloads in `ModuleCRC21` and `ModuleCRC20` to revert unconditionally, mirroring the fix applied in the referenced audit:

```solidity
// In ModuleCRC21 and ModuleCRC20
function burn(uint wad) public override {
    revert("ModuleCRC21: burn disabled");
}

function burn(address guy, uint wad) public override {
    revert("ModuleCRC21: burn disabled");
}
```

All legitimate burn paths already go through `unsafe_burn` (private/internal) invoked by `send_to_ibc`, `send_to_evm_chain`, `send_to_ethereum`, and `burn_by_cronos_module`, so disabling the inherited public functions has no effect on correct protocol operation. [7](#0-6) [8](#0-7) 

---

### Proof of Concept

```
// Attacker holds or is approved for CRC21 tokens representing IBC vouchers

// Step 1 (self-burn): attacker calls directly on the ModuleCRC21 contract
ModuleCRC21(crc21Address).burn(1_000e18);
// → tokens destroyed, NO __CronosSendToIbc event emitted
// → IBC escrow on source chain retains the native tokens permanently

// Step 2 (burnFrom analog): victim approved attacker for a DEX swap
// attacker calls:
ModuleCRC21(crc21Address).burn(victimAddress, 1_000e18);
// → victim's CRC21 tokens destroyed, allowance consumed
// → no bridge credit issued, native tokens permanently locked in escrow
```

The Cronos EVM hook layer only processes `__CronosSendToIbc` / `__CronosSendToEvmChain` log events; since neither is emitted, the module never releases the escrowed native assets, creating a permanent supply/escrow mismatch. [9](#0-8) [10](#0-9)

### Citations

**File:** contracts/src/ModuleCRC21.sol (L1-9)
```text
pragma solidity ^0.6.1;

import "ds-token/token.sol";

contract ModuleCRC21 is DSToken {
    // sha256('cronos-evm')[:20]
    address constant module_address = 0x89A7EF2F08B1c018D5Cc88836249b84Dd5392905;
    string denom;
    bool isSource;
```

**File:** contracts/src/ModuleCRC21.sol (L41-44)
```text
    function burn_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        unsafe_burn(addr, amount);
    }
```

**File:** contracts/src/ModuleCRC21.sol (L59-67)
```text
    // send an "amount" of the contract token to recipient through IBC
    function send_to_ibc(string memory recipient, uint amount, uint channel_id, bytes memory extraData) public {
        if (isSource) {
            transferFrom(msg.sender, module_address, amount);
        } else {
            unsafe_burn(msg.sender, amount);
        }
        emit __CronosSendToIbc(msg.sender, channel_id, recipient, amount, extraData);
    }
```

**File:** contracts/src/ModuleCRC21.sol (L88-95)
```text
    // unsafe_burn burn tokens without user's approval and authentication, used internally
    function unsafe_burn(address addr, uint amount) internal {
        // Deduct user's balance without approval
        require(balanceOf[addr] >= amount, "ds-token-insufficient-balance");
        balanceOf[addr] = sub(balanceOf[addr], amount);
        totalSupply = sub(totalSupply, amount);
        emit Burn(addr, amount);
    }
```

**File:** contracts/src/ModuleCRC20.sol (L1-5)
```text
pragma solidity ^0.6.8;

import "ds-token/token.sol";

contract ModuleCRC20 is DSToken  {
```

**File:** contracts/src/ModuleCRC20.sol (L36-39)
```text
    function burn_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        unsafe_burn(addr, amount);
    }
```

**File:** contracts/src/ModuleCRC20.sol (L48-51)
```text
    function send_to_ibc(string memory recipient, uint amount) public {
        unsafe_burn(msg.sender, amount);
        emit __CronosSendToIbc(msg.sender, recipient, amount);
    }
```

**File:** x/cronos/types/contracts/ModuleCRC21.json (L348-378)
```json
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "wad",
          "type": "uint256"
        }
      ],
      "name": "burn",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "guy",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "wad",
          "type": "uint256"
        }
      ],
      "name": "burn",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
```

**File:** x/cronos/types/contracts/ModuleCRC20.json (L301-324)
```json
      ],
      "name": "burn",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "guy",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "wad",
          "type": "uint256"
        }
      ],
      "name": "burn",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
```
