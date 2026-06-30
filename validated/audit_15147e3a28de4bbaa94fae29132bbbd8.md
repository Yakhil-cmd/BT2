### Title
ERC-20 Approve Race Condition in EvmErc20/EvmErc20V2 Allows Front-Running to Steal Bridged Tokens - (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

The `EvmErc20` and `EvmErc20V2` contracts, which are the production ERC-20 mirror contracts deployed by Aurora Engine for every bridged NEP-141 token, inherit OpenZeppelin's `ERC20.approve` without any race-condition mitigation. When a token holder attempts to change an existing non-zero allowance to a new non-zero value, an approved spender can front-run the approval change transaction to spend both the old and the new allowance, stealing more tokens than the owner ever intended to authorize.

---

### Finding Description

Aurora Engine deploys an ERC-20 mirror contract for every NEP-141 token bridged into the EVM environment. The bytecode for these mirrors is embedded directly in the engine binary at build time: [1](#0-0) 

The two variants are `EvmErc20` and `EvmErc20V2`, both of which inherit from OpenZeppelin's `ERC20`: [2](#0-1) 

Neither contract overrides `approve`, adds `increaseAllowance`/`decreaseAllowance`, nor requires the current allowance to be zero before setting a new value. The inherited OpenZeppelin `approve` unconditionally overwrites `_allowances[owner][spender]` with the new amount.

The attack proceeds as follows:

1. Alice has previously approved Bob for `N` tokens: `approve(Bob, N)`.
2. Alice decides to reduce Bob's allowance to `M` (where `M < N`) and submits `approve(Bob, M)`.
3. Bob observes Alice's pending `approve(Bob, M)` transaction in the NEAR mempool (Aurora EVM transactions are submitted via the NEAR `submit` entrypoint and are publicly visible before inclusion).
4. Bob front-runs Alice's transaction by submitting `transferFrom(Alice, Bob, N)` with a higher gas price, spending the full old allowance of `N` tokens.
5. Alice's `approve(Bob, M)` executes, setting the allowance to `M`.
6. Bob calls `transferFrom(Alice, Bob, M)` again, spending the new allowance.
7. Bob has transferred `N + M` tokens from Alice, far exceeding Alice's intended authorization of `M`.

The `mint` function is restricted to the admin (the Aurora Engine contract address), so the supply is not inflated — the attack is purely a theft of Alice's existing token balance. [3](#0-2) 

---

### Impact Explanation

**Critical — Direct theft of user funds.**

An unprivileged EVM user (Bob) can steal an arbitrary multiple of the victim's intended allowance from any holder of any bridged NEP-141 ERC-20 token on Aurora. Because every NEP-141 bridge token (wNEAR, USDC, USDT, etc.) is deployed as an instance of `EvmErc20` or `EvmErc20V2`, the attack surface covers all bridged assets on the network. The stolen tokens are real bridged assets backed 1:1 by NEP-141 tokens held by the Aurora Engine contract, so the loss is permanent and unrecoverable without a protocol-level intervention.

---

### Likelihood Explanation

**Medium.** The precondition is that a victim must change an existing non-zero allowance to a different non-zero value — a routine DeFi operation (e.g., adjusting a DEX router's spending limit). Aurora EVM transactions are submitted as NEAR transactions via the `submit` entrypoint and are visible in the NEAR mempool before block inclusion, making mempool observation straightforward. A sophisticated attacker running a mempool monitor can reliably detect and front-run such transactions. The attack requires no special privileges, no admin access, and no external dependencies.

---

### Recommendation

1. **Short term**: Require the allowance to be set to zero before changing it to a non-zero value, or document this behavior prominently so users know to always reset allowances to zero between changes.

2. **Long term**: Override `approve` in `EvmErc20` and `EvmErc20V2` to revert if the current allowance is non-zero and the new amount is also non-zero, forcing a two-step `approve(0)` → `approve(N)` pattern. Alternatively, expose `increaseAllowance` and `decreaseAllowance` as the recommended interface for adjusting existing allowances, which are immune to this race condition.

---

### Proof of Concept

```
1. Alice holds 1000 bridged USDC (EvmErc20V2 instance).
2. Alice calls: approve(Bob, 500)  → allowance[Alice][Bob] = 500
3. Alice decides to reduce: approve(Bob, 100)  [pending in mempool]
4. Bob sees the pending tx; submits transferFrom(Alice, Bob, 500) with higher gas.
   → Bob receives 500 USDC; allowance[Alice][Bob] = 0
5. Alice's approve(Bob, 100) executes.
   → allowance[Alice][Bob] = 100
6. Bob calls transferFrom(Alice, Bob, 100).
   → Bob receives another 100 USDC.

Net result: Bob stole 600 USDC; Alice intended to authorize only 100.
```

The entry path is entirely through the standard ERC-20 interface of the deployed `EvmErc20V2` contract, reachable by any unprivileged EVM user via the Aurora Engine `submit` entrypoint. [4](#0-3) [5](#0-4)

### Citations

**File:** engine/src/engine.rs (L1316-1337)
```rust
#[must_use]
pub fn setup_deploy_erc20_input(
    current_account_id: &AccountId,
    erc20_metadata: Option<Erc20Metadata>,
) -> Vec<u8> {
    #[cfg(feature = "error_refund")]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20V2.bin");
    #[cfg(not(feature = "error_refund"))]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20.bin");

    let erc20_admin_address = current_address(current_account_id);
    let erc20_metadata = erc20_metadata.unwrap_or_default();

    let deploy_args = ethabi::encode(&[
        ethabi::Token::String(erc20_metadata.name),
        ethabi::Token::String(erc20_metadata.symbol),
        ethabi::Token::Uint(erc20_metadata.decimals.into()),
        ethabi::Token::Address(erc20_admin_address.raw().0.into()),
    ]);

    [erc20_contract, deploy_args.as_slice()].concat()
}
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L1-15)
```text
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./AdminControlled.sol";
import "./IExit.sol";


/**
 * @title SimpleToken
 * @dev Very simple ERC20 Token example, where all tokens are pre-assigned to the creator.
 * Note they can later distribute these tokens as they wish using `transfer` and other
 * `ERC20` functions.
 */
contract EvmErc20V2 is ERC20, AdminControlled, IExit {
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L49-51)
```text
    function mint(address account, uint256 amount) public onlyAdmin {
        _mint(account, amount);
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
```
