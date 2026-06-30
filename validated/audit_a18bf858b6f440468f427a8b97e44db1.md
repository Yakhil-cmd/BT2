### Title
ERC-20 `approve()` Race Condition Allows Double-Spend of Bridge Token Allowances - (File: `etc/eth-contracts/contracts/EvmErc20.sol`)

### Summary
The `EvmErc20` bridge token contract inherits OpenZeppelin's standard `approve()` function without any mitigation for the well-known ERC-20 allowance race condition. When a token holder attempts to change an existing non-zero allowance to a new non-zero value, a front-running spender can drain both the old and new allowances, stealing more tokens than the owner ever intended to authorize.

### Finding Description
`EvmErc20` is Aurora's production ERC-20 mirror contract for NEP-141 bridged tokens. It inherits from OpenZeppelin's `ERC20.sol` and exposes the standard `approve(address spender, uint256 amount)` function without override. [1](#0-0) 

The inherited `approve()` unconditionally overwrites the current allowance mapping entry with the new value. There is no check that the current allowance is zero before setting a new one, and no `increaseAllowance`/`decreaseAllowance` alternative is provided in the contract. [2](#0-1) 

The contract is deployed by the Aurora Engine connector when a NEP-141 token is bridged, making it the canonical ERC-20 representation of real bridged assets held by users. [3](#0-2) 

### Impact Explanation
**Critical — Direct theft of user funds.**

A malicious or opportunistic spender who already holds a non-zero allowance can observe a pending `approve()` transaction that would reduce their allowance, front-run it by spending the full old allowance via `transferFrom`, and then spend the newly set allowance after the victim's transaction confirms. The net result is the spender drains `old_allowance + new_allowance` worth of bridged tokens from the victim's balance, which are real assets locked in the NEAR bridge.

### Likelihood Explanation
**Medium.** Aurora processes Ethereum-format transactions through NEAR relayers. Relayers see submitted transactions before they are included in a NEAR block. A malicious relayer, or any party who can observe the Aurora transaction pool (e.g., via a public RPC endpoint), can detect a victim's `approve()` call that lowers an existing allowance and reorder or insert a `transferFrom` ahead of it. No special privilege is required beyond already holding a non-zero allowance granted by the victim.

### Recommendation
**Short term:** Override `approve()` in `EvmErc20` to revert when the caller attempts to change a non-zero allowance to another non-zero value, requiring the allowance to be set to zero first as an intermediate step.

**Long term:** Expose `increaseAllowance` and `decreaseAllowance` functions (or EIP-2612 `permit`) in `EvmErc20` and `EvmErc20V2` so users can safely adjust allowances atomically without the two-step race window.

### Proof of Concept
1. Alice holds 200 bridge tokens (EvmErc20 for `wrap.near`). She previously called `approve(Bob, 100)`.
2. Alice decides to reduce Bob's allowance and submits `approve(Bob, 50)`.
3. Bob (or a monitoring relayer) sees Alice's pending transaction. Bob immediately submits `transferFrom(Alice, Bob, 100)` with a higher priority.
4. Bob's `transferFrom` is included first: Bob receives 100 tokens; Alice's balance is now 100.
5. Alice's `approve(Bob, 50)` is then included: Bob's allowance is now 50.
6. Bob calls `transferFrom(Alice, Bob, 50)`: Bob receives 50 more tokens.
7. **Net result:** Bob has stolen 150 tokens. Alice intended to authorize at most 50.

The entry path is fully unprivileged: any EVM address that holds a non-zero allowance on any `EvmErc20` mirror token can execute this attack against the token owner. [4](#0-3)

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L1-60)
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
contract EvmErc20 is ERC20, AdminControlled, IExit {
    string private _name;
    string private _symbol;
    uint8 private _decimals;

    // slither-disable-next-line shadowing-local
    constructor (string memory metadata_name, string memory metadata_symbol, uint8 metadata_decimals, address admin)
        ERC20(metadata_name, metadata_symbol)
        AdminControlled(admin, 0)
    {
        _name = metadata_name;
        _symbol = metadata_symbol;
        _decimals = metadata_decimals;
    }

    function name() public view override returns (string memory) {
        return _name;
    }

    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    // slither-disable-next-line events-maths
    function setMetadata(string memory metadata_name, string memory metadata_symbol, uint8 metadata_decimals) external onlyAdmin {
        _name = metadata_name;
        _symbol = metadata_symbol;
        _decimals = metadata_decimals;
    }

    function mint(address account, uint256 amount) public onlyAdmin {
        _mint(account, amount);
    }

    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
```

**File:** engine/src/contract_methods/connector.rs (L1-1)
```rust
use aurora_engine_modexp::AuroraModExp;
```
