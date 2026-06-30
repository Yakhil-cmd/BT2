### Title
`is_allow_receive_erc20_tokens()` Ignores `EvmAdmin` Whitelist, Causing Permanent Misdirection of Bridged ERC-20 Tokens for EVM-Admin Addresses — (`engine/src/contract_methods/silo/mod.rs`)

---

### Summary

In Silo mode, `Engine::receive_erc20_tokens()` redirects bridged ERC-20 tokens to a fallback address when `is_allow_receive_erc20_tokens()` returns `false` for the intended recipient. That function only checks the `WhitelistKind::Address` list. It does **not** check `WhitelistKind::EvmAdmin`. An EVM address that is whitelisted as an `EvmAdmin` (permitted to deploy contracts) but is not separately enrolled in the `Address` list will be treated as an unauthorized recipient, and its bridged tokens will be permanently minted to the fallback address instead.

---

### Finding Description

`is_allow_receive_erc20_tokens()` is defined as:

```rust
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)   // only checks WhitelistKind::Address
}
``` [1](#0-0) 

`is_address_allowed` exclusively consults `WhitelistKind::Address`:

```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
``` [2](#0-1) 

It never consults `WhitelistKind::EvmAdmin`, which is the separate list for EVM addresses that are privileged to deploy contracts:

```rust
fn is_address_allowed_deploy<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::EvmAdmin);
    !list.is_enabled() || list.is_exist(address)
}
``` [3](#0-2) 

The call site in `receive_erc20_tokens()` silently replaces the intended recipient with the fallback address when the check fails:

```rust
if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
    && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
{
    recipient = fallback_address;
}
``` [4](#0-3) 

The ERC-20 mint then proceeds against the substituted fallback address, not the original recipient:

```rust
setup_receive_erc20_tokens_input(&recipient, amount)
``` [5](#0-4) 

The `WhitelistKind` documentation explicitly states that `EvmAdmin` addresses are privileged actors in the silo:

```rust
/// The whitelist of this type is for storing EVM addresses. Addresses included in this
/// whitelist can deploy EVM code.
EvmAdmin = 0x1,
``` [6](#0-5) 

A silo operator will commonly add a deployer address to `EvmAdmin` without also adding it to `Address` (the transaction-submission list), because the two roles are intentionally separate. When that `EvmAdmin` address later receives bridged NEP-141 tokens via `ft_on_transfer`, the engine silently mints the ERC-20 tokens to the fallback address instead.

---

### Impact Explanation

**Impact: High — Theft of user funds (bridged tokens permanently misdirected)**

The NEP-141 tokens are consumed on the NEAR side (the bridge transfer is accepted and returns `"0"` to the caller, signalling full consumption). The corresponding ERC-20 tokens are minted to the fallback address, not to the `EvmAdmin` recipient. The `EvmAdmin` address permanently loses the bridged value with no on-chain error or revert. Recovery requires the silo operator to manually return the tokens from the fallback address, which is an off-chain, trust-dependent action.

---

### Likelihood Explanation

**Likelihood: Medium**

The preconditions are:
1. Silo mode is active (fallback address configured via `set_silo_params`).
2. The `Address` whitelist is enabled.
3. An EVM address is enrolled in `EvmAdmin` but not in `Address`.

Condition 3 is a natural operational state: a silo operator grants deploy rights to a contract-deployer address without granting it general transaction-submission rights. This is the intended purpose of having two separate EVM-address whitelists. The misdirection then occurs automatically on any `ft_on_transfer` call targeting that address.

---

### Recommendation

`is_allow_receive_erc20_tokens()` should also return `true` for addresses present in `WhitelistKind::EvmAdmin`:

```rust
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address) || is_address_allowed_deploy(io, address)
}
```

This mirrors the pattern used by `is_allow_deploy`, which combines both the `Admin` (NEAR account) and `EvmAdmin` (EVM address) checks, ensuring that privileged addresses are not inadvertently excluded from receiving tokens. [7](#0-6) 

---

### Proof of Concept

1. Deploy Aurora Engine in Silo mode: call `set_silo_params` with a non-zero `erc20_fallback_address` (e.g. `0xFALL...`).
2. Enable the `Address` whitelist via `set_whitelist_status(WhitelistKind::Address, active: true)`.
3. Add EVM address `0xEVMAdmin` to `WhitelistKind::EvmAdmin` only (do **not** add it to `WhitelistKind::Address`).
4. Deploy a NEP-141 token and its ERC-20 mirror via `deploy_erc20_token`.
5. Call `ft_transfer_call` on the NEP-141 contract, transferring 100 tokens to the Aurora engine with `msg = "0xEVMAdmin..."`.
6. The engine calls `receive_erc20_tokens`. `is_allow_receive_erc20_tokens(&io, &0xEVMAdmin)` checks only `WhitelistKind::Address` → returns `false`.
7. `recipient` is overwritten with `0xFALL...`.
8. `EvmErc20.mint(0xFALL..., 100)` is executed.
9. Observe: `balanceOf(0xEVMAdmin)` = 0; `balanceOf(0xFALL...)` = 100. The 100 NEP-141 tokens are permanently lost to the `EvmAdmin` address. [8](#0-7) [1](#0-0)

### Citations

**File:** engine/src/contract_methods/silo/mod.rs (L130-133)
```rust
/// Check if a user has the right to deploy EVM code.
pub fn is_allow_deploy<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_account_allowed_deploy(io, account) && is_address_allowed_deploy(io, address)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L140-143)
```rust
/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L150-153)
```rust
fn is_address_allowed_deploy<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::EvmAdmin);
    !list.is_enabled() || list.is_exist(address)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L155-158)
```rust
fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}
```

**File:** engine/src/engine.rs (L818-839)
```rust
        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }

        let erc20_token = get_erc20_from_nep141(&self.io, token)?;
        let erc20_admin_address = current_address(current_account_id);
        let result = self
            .call(
                &erc20_admin_address,
                &erc20_token,
                Wei::zero(),
                setup_receive_erc20_tokens_input(&recipient, amount),
                u64::MAX,
                Vec::new(), // TODO: are there values we should put here?
                Vec::new(),
                handler,
            )
            .and_then(submit_result_or_err)?;

        sdk::log!("Mint {amount} ERC-20 tokens for: {}", recipient.encode());
```

**File:** engine-types/src/parameters/silo.rs (L72-73)
```rust
    /// whitelist can deploy EVM code.
    EvmAdmin = 0x1,
```
