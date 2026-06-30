### Title
Silo Address Whitelist Not Enforced on ERC-20 Spender (`msg.sender`) in `transferFrom` — (File: `engine/src/contract_methods/silo/mod.rs`)

---

### Summary

In Silo mode, the `WhitelistKind::Address` whitelist is enforced on the **recipient** of ERC-20 tokens via `is_allow_receive_erc20_tokens`, but is never checked against the **spender** — the EVM address that appears as `msg.sender` inside the EVM when a contract calls `transferFrom` on behalf of a token owner. A non-whitelisted contract holding an ERC-20 allowance from a whitelisted user can call `transferFrom` to drain that user's tokens, bypassing the silo whitelist entirely for the spender role.

---

### Finding Description

The silo whitelist system enforces access control at exactly two points:

**Point 1 — Transaction origin check (`is_allow_submit`):**
Before any EVM execution begins, the engine validates the NEAR `AccountId` and the EVM address of the **outermost transaction sender**. [1](#0-0) 

This check covers only the NEAR-level origin. Any contract invoked as an intermediate step in the EVM call stack is never re-validated.

**Point 2 — Recipient check (`is_allow_receive_erc20_tokens`):**
When an ERC-20 transfer occurs, the engine checks the **recipient** EVM address against the `WhitelistKind::Address` list. If the recipient is not whitelisted, tokens are redirected to the `erc20_fallback_address`. [2](#0-1) 

The underlying check delegates to `is_address_allowed`, which reads the `WhitelistKind::Address` list: [3](#0-2) 

**The gap:** Neither check covers the **spender** — the EVM address (`msg.sender` inside the EVM) that calls `transferFrom`. When a whitelisted user grants an ERC-20 allowance to a non-whitelisted contract, that contract can invoke `transferFrom` as the spender. The engine's only ERC-20 whitelist gate (`is_allow_receive_erc20_tokens`) evaluates the recipient, not the spender, so the non-whitelisted contract's status is never evaluated.

This is structurally identical to the USDKG analog: `transferFrom` checks one party (`_from` / recipient) but omits the check on the spender (`msg.sender` in EVM context).

---

### Impact Explanation

A non-whitelisted contract (spender) holding an ERC-20 allowance from a whitelisted user calls `transferFrom(whitelistedUser, whitelistedRecipient, amount)`. The engine's only ERC-20 whitelist check passes because the recipient is whitelisted. The spender's non-whitelisted status is never evaluated. The non-whitelisted contract moves tokens out of the whitelisted user's balance without restriction.

**Impact: Critical** — Direct theft of user funds at rest.

---

### Likelihood Explanation

The attack requires three conditions:

1. A whitelisted user has granted an ERC-20 allowance to a non-whitelisted contract (e.g., by interacting with a DeFi protocol or any contract deployed outside the whitelist).
2. A whitelisted NEAR account submits a transaction that triggers the non-whitelisted contract — the origin check (`is_allow_submit`) passes because the outermost caller is whitelisted.
3. The attacker's receiving address is whitelisted — so the recipient check (`is_allow_receive_erc20_tokens`) passes.

In a silo deployment where users interact with multiple contracts and many addresses are whitelisted, conditions 1 and 3 are realistic. **Likelihood: Medium.**

---

### Recommendation

Apply the `WhitelistKind::Address` check to the **spender** (`msg.sender` in the EVM context) in addition to the recipient when the engine intercepts ERC-20 `transferFrom` operations. Concretely, extend the engine's ERC-20 transfer interception logic to call `is_allow_receive_erc20_tokens` (or an equivalent `is_address_allowed` call) on the spender address, mirroring the existing recipient check. [2](#0-1) 

---

### Proof of Concept

1. Silo mode is active; `WhitelistKind::Address` whitelist is enabled.
2. Alice (`0xAlice`, whitelisted) calls `approve(0xMalicious, 1000)` on a silo ERC-20 token. `0xMalicious` is a non-whitelisted contract.
3. Attacker (`0xAttacker`, whitelisted) submits a NEAR transaction calling `0xMalicious`. `is_allow_submit` passes because the NEAR-level origin maps to a whitelisted EVM address. [1](#0-0) 

4. Inside the EVM, `0xMalicious` calls `transferFrom(0xAlice, 0xAttacker, 1000)`. The EVM `msg.sender` for this call is `0xMalicious`.
5. The engine calls `is_allow_receive_erc20_tokens(0xAttacker)` → passes (`0xAttacker` is whitelisted). [2](#0-1) 

6. The spender `0xMalicious` is never checked against the `WhitelistKind::Address` list. [4](#0-3) 

7. 1000 tokens are transferred from Alice to Attacker. Alice's funds are stolen with no whitelist enforcement on the spender.

### Citations

**File:** engine/src/contract_methods/silo/mod.rs (L136-138)
```rust
pub fn is_allow_submit<I: IO + Copy>(io: &I, account: &AccountId, address: &Address) -> bool {
    is_address_allowed(io, address) && is_account_allowed(io, account)
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L141-143)
```rust
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

**File:** engine/src/contract_methods/silo/whitelist.rs (L70-73)
```rust
    pub fn is_exist<A: AsBytes + ?Sized>(&self, element: &A) -> bool {
        let key = self.key(element.as_bytes());
        self.io.storage_has_key(&key)
    }
```
