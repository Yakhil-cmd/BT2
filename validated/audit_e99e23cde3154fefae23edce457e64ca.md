### Title
Asymmetric Silo Whitelist Enforcement Allows ERC-20 Token Receipt But Blocks All Exit Paths - (`engine/src/contract_methods/silo/mod.rs`)

---

### Summary

In Aurora Engine's Silo mode, the access control check for **receiving** ERC-20 tokens (`is_allow_receive_erc20_tokens`) only validates the `Address` whitelist, while the check for **submitting** EVM transactions (`is_allow_submit`) requires **both** the `Address` and `Account` whitelists. A user whose EVM address is in the `Address` whitelist but whose NEAR account ID is absent from the `Account` whitelist can receive ERC-20 tokens via `ft_on_transfer`, but cannot submit any EVM transaction to transfer, swap, or withdraw those tokens. The tokens are frozen until governance intervenes.

---

### Finding Description

The Silo module exposes two distinct access-control predicates:

**`is_allow_submit`** — gates all EVM transaction submission: [1](#0-0) 

```rust
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
```

**`is_allow_receive_erc20_tokens`** — gates ERC-20 token receipt via `ft_on_transfer`: [2](#0-1) 

```rust
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}
```

The `Account` whitelist (`WhitelistKind::Account`) stores NEAR account IDs and is required for submitting transactions: [3](#0-2) 

The `Address` whitelist (`WhitelistKind::Address`) stores EVM addresses and is the **only** check for receiving ERC-20 tokens: [4](#0-3) 

The four whitelist kinds are defined as: [5](#0-4) 

The `ft_on_transfer` entrypoint calls `engine.receive_erc20_tokens(...)` when the predecessor is not the ETH connector: [6](#0-5) 

This means: a user whose EVM address is in the `Address` whitelist can receive ERC-20 tokens from any whitelisted sender. However, to do anything with those tokens — transfer them, call a DEX, or invoke the `exit_to_near` precompile — the user must submit an EVM transaction, which requires their NEAR account ID to also be in the `Account` whitelist. If it is not, every `submit` or `call` attempt is rejected with `NotAllowed`, and the tokens are stuck.

---

### Impact Explanation

**High — Temporary freezing of funds.**

ERC-20 tokens credited to an EVM address that is in the `Address` whitelist but whose corresponding NEAR account is absent from the `Account` whitelist are completely immovable by the owner. The owner cannot:
- Transfer the ERC-20 tokens to another address (requires `submit`).
- Call any contract (requires `submit`/`call`).
- Invoke the `exit_to_near` precompile to bridge out (requires `submit`).

The tokens remain frozen until the Silo operator adds the NEAR account to the `Account` whitelist or disables that whitelist entirely. This matches the "temporary freezing of funds" impact category.

---

### Likelihood Explanation

The scenario is realistic in any Silo deployment where:
1. The `Address` whitelist is enabled and populated (e.g., a curated set of EVM addresses allowed to hold tokens).
2. The `Account` whitelist is also enabled but maintained separately (e.g., only relayer NEAR accounts are listed).
3. A whitelisted EVM address receives ERC-20 tokens via `ft_on_transfer` from another user or protocol.

This is not a hypothetical configuration — the Silo design explicitly separates `Address` and `Account` whitelists as independent lists: [7](#0-6) 

The asymmetry is structural: the receive path checks one dimension, the send/exit path checks two.

---

### Recommendation

Align the access control check in `is_allow_receive_erc20_tokens` with `is_allow_submit` by also requiring the `Account` whitelist, **or** introduce a dedicated exit-path check that mirrors the entry-path check exactly. Alternatively, document and enforce the invariant that any EVM address added to the `Address` whitelist must have a corresponding NEAR account in the `Account` whitelist before tokens can be credited to it.

---

### Proof of Concept

1. Silo operator enables all whitelists and adds EVM address `0xALICE` to the `Address` whitelist, but does **not** add Alice's NEAR account `alice.near` to the `Account` whitelist.
2. A whitelisted sender calls `ft_transfer_call` on an ERC-20 NEP-141 token, routing tokens to Aurora with `receiver_id = 0xALICE`. `ft_on_transfer` → `receive_erc20_tokens` succeeds because `is_allow_receive_erc20_tokens` only checks the `Address` whitelist.
3. Alice now holds ERC-20 tokens inside Aurora. She attempts to transfer them by submitting an EVM transaction via `submit`. The engine calls `is_allow_submit(io, "alice.near", 0xALICE)`, which evaluates `is_account_allowed` → `Account` whitelist is enabled and `alice.near` is absent → returns `false` → `NotAllowed` error.
4. Alice cannot transfer, swap, or bridge out her tokens. They are frozen until governance adds `alice.near` to the `Account` whitelist. [8](#0-7)

### Citations

**File:** engine/src/contract_methods/silo/mod.rs (L135-163)
```rust
/// Check if a user has the right to submit transactions.
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}

/// Check if a user has the right to receive erc20 tokens.
pub fn is_allow_receive_erc20_tokens<I: IO + Copy>(io: &I, address: &Address) -> bool {
    is_address_allowed(io, address)
}

fn is_account_allowed_deploy<I: IO + Copy>(io: &I, account_id: &AccountId) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Admin);
    !list.is_enabled() || list.is_exist(account_id)
}

fn is_address_allowed_deploy<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::EvmAdmin);
    !list.is_enabled() || list.is_exist(address)
}

fn is_address_allowed<I: IO + Copy>(io: &I, address: &Address) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Address);
    !list.is_enabled() || list.is_exist(address)
}

fn is_account_allowed<I: IO + Copy>(io: &I, account: &AccountId) -> bool {
    let list = Whitelist::init(io, WhitelistKind::Account);
    !list.is_enabled() || list.is_exist(account)
}
```

**File:** engine/src/contract_methods/connector.rs (L81-90)
```rust
        let result = if predecessor_account_id == get_connector_account_id(&io)? {
            engine.receive_base_tokens(&args)
        } else {
            engine.receive_erc20_tokens(
                &predecessor_account_id,
                &args,
                &current_account_id,
                handler,
            )
        };
```

**File:** engine-types/src/parameters/silo.rs (L62-80)
```rust
#[derive(Debug, Copy, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
#[borsh(use_discriminant = false)]
pub enum WhitelistKind {
    /// The whitelist of this type is for storing NEAR accounts. Accounts stored in this whitelist
    /// have an admin role. The admin role allows to add new admins and add new entities
    /// (`AccountId` and `Address`) to whitelists. Also, this role allows to deploy of EVM code
    /// and submit transactions.
    Admin = 0x0,
    /// The whitelist of this type is for storing EVM addresses. Addresses included in this
    /// whitelist can deploy EVM code.
    EvmAdmin = 0x1,
    /// The whitelist of this type is for storing NEAR accounts. Accounts included in this
    /// whitelist can submit transactions.
    Account = 0x2,
    /// The whitelist of this type is for storing EVM addresses. Addresses included in this
    /// whitelist can submit transactions.
    Address = 0x3,
}
```
