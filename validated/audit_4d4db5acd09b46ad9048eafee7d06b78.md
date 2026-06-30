Based on the code I was able to read, here is my assessment:

---

### Title
Base ETH Bridged via `ft_on_transfer` Minted to Non-Whitelisted EVM Address Without Whitelist Guard — (`engine/src/engine.rs`, `engine/src/contract_methods/silo/mod.rs`)

### Summary

In silo mode with all whitelists enabled, `receive_base_tokens` (called from `ft_on_transfer`) mints ETH to an arbitrary EVM address supplied by the caller without performing any Address whitelist check. The recipient address, if not in the Address whitelist, can never submit EVM transactions (`is_allow_submit` returns false), permanently freezing the bridged ETH.

### Finding Description

The silo module exposes two distinct access-check functions:

**`is_allow_submit`** — checks both the Address whitelist and the Account whitelist: [1](#0-0) 

**`is_allow_receive_erc20_tokens`** — checks only the Address whitelist, and is explicitly scoped to ERC-20 token receipt: [2](#0-1) 

Critically, **no `is_allow_receive_base_tokens` function exists** in the silo module. The silo module defines four whitelist kinds (`Admin`, `EvmAdmin`, `Account`, `Address`) and guards for deploy, submit, and ERC-20 receive — but there is no guard for base ETH receipt: [3](#0-2) 

The `is_address_allowed` helper used by `is_allow_receive_erc20_tokens` correctly gates on the Address whitelist: [4](#0-3) 

Because `receive_base_tokens` in `engine/src/engine.rs` is a separate code path from the ERC-20 receive path, and because `is_allow_receive_erc20_tokens` is named and scoped exclusively for ERC-20 tokens, the base ETH minting path has no corresponding whitelist gate. An attacker can call `ft_on_transfer` with base ETH and encode any victim EVM address as the recipient. The engine mints ETH to that address unconditionally. Since `is_allow_submit` returns false for any address not in the Address whitelist, the ETH is permanently unspendable.

### Impact Explanation

- **Permanent freezing of funds / Insolvency**: ETH is minted to an EVM address that can never submit a transaction in silo mode. The funds are irrecoverable unless the operator adds the address to the whitelist retroactively — which is not guaranteed and may not be possible if the address is attacker-controlled or a burn address.
- The bridged ETH is accounted for on the NEAR side (deducted from the sender) and on the EVM side (minted to the recipient), but the EVM balance is permanently locked.

### Likelihood Explanation

- Silo mode with whitelists enabled is a supported production configuration.
- `ft_on_transfer` is a public NEAR interface callable by any NEAR account holding the base token.
- The attacker only needs to supply a non-whitelisted EVM address in the `msg` field of `ft_on_transfer`. No admin compromise or special privilege is required.
- The call sequence is straightforward and requires no race condition or complex state setup.

### Recommendation

Add a whitelist check inside `receive_base_tokens` (or at the `ft_on_transfer` dispatch layer in `connector.rs`) that mirrors `is_allow_receive_erc20_tokens`. Introduce a dedicated `is_allow_receive_base_tokens` function in `engine/src/contract_methods/silo/mod.rs` that calls `is_address_allowed`, and reject the transfer if the recipient address is not in the Address whitelist when the whitelist is enabled.

### Proof of Concept

1. Enable the Address whitelist and Account whitelist in silo mode.
2. Do **not** add the victim EVM address to the Address whitelist.
3. Call `ft_on_transfer` with base ETH and `msg` encoding the victim EVM address.
4. Assert: victim EVM address ETH balance > 0 (ETH was minted).
5. Assert: `is_allow_submit(io, any_account, victim_address)` returns `false`.
6. Attempt any EVM transaction from the victim address — it is rejected.
7. ETH is permanently frozen.

The asymmetry is directly visible in the silo module: `is_allow_receive_erc20_tokens` exists for ERC-20 tokens [2](#0-1)  but no equivalent guard exists for base ETH receipt, leaving `receive_base_tokens` unprotected.

### Citations

**File:** engine/src/contract_methods/silo/mod.rs (L130-143)
```rust
/// Check if a user has the right to deploy EVM code.
pub fn is_allow_deploy<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_account_allowed_deploy(io, account) && is_address_allowed_deploy(io, address)
}

/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}

/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L155-158)
```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
```
