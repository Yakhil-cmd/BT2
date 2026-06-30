### Title
Fee-on-Transfer NEP-141 Token Bridge Mints Unbacked ERC-20 Tokens, Causing Insolvency — (`engine/src/engine.rs`)

---

### Summary

Aurora's NEP-141 → ERC-20 bridge unconditionally trusts the `amount` field supplied in the `ft_on_transfer` callback and mints that exact quantity of ERC-20 tokens. For NEP-141 tokens that silently deduct a fee during transfer (fee-on-transfer tokens), the actual balance credited to Aurora is `amount − fee`, while the ERC-20 mirror mints the full `amount`. The resulting over-issuance is permanent and exploitable: an attacker can sell the unbacked ERC-20 tokens on-chain, leaving later redeemers unable to exit.

---

### Finding Description

**Vulnerable function:** `Engine::receive_erc20_tokens` in `engine/src/engine.rs`

The `ft_on_transfer` NEAR entry-point dispatches to `receive_erc20_tokens` for every non-base-token NEP-141 deposit:

```rust
// engine/src/contract_methods/connector.rs  (ft_on_transfer)
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

Inside `receive_erc20_tokens`, the mint amount is taken verbatim from the callback argument:

```rust
// engine/src/engine.rs  receive_erc20_tokens
let amount = args.amount.as_u128();          // ← amount the caller *claimed* to send
// ...
setup_receive_erc20_tokens_input(&recipient, amount)  // mints `amount` ERC-20 tokens
```

`args.amount` is the value the NEP-141 contract passes to `ft_on_transfer`. For a fee-on-transfer NEP-141 token, the contract transfers `amount − fee` tokens to Aurora but still invokes `ft_on_transfer` with the original `amount`. Aurora never queries its own NEP-141 balance before and after the transfer; it simply trusts the callback parameter.

`deploy_erc20_token` contains no access-control guard:

```rust
// engine/src/contract_methods/connector.rs  deploy_erc20_token
require_running(&state::get_state(&io)?)?;
// ← no require_owner_only, no whitelist check
let args = DeployErc20TokenArgs::deserialize(&bytes)...;
```

Any unprivileged account can register an arbitrary NEP-141 token and obtain an ERC-20 mirror on Aurora.

---

### Impact Explanation

**Critical — Insolvency / Direct theft of user funds.**

After bridging `N` tokens of a fee-on-transfer NEP-141 (fee rate `f`):

| Quantity | Value |
|---|---|
| NEP-141 tokens held by Aurora | `N × (1 − f)` |
| ERC-20 tokens minted on Aurora | `N` |
| Unbacked ERC-20 tokens | `N × f` |

The attacker sells the full `N` ERC-20 tokens on an Aurora DEX. Buyers who later attempt to exit via `withdrawToNear` (which burns ERC-20 and calls `ft_transfer` on the NEP-141 contract) find that Aurora's NEP-141 balance is insufficient. The `N × f` shortfall is permanent: those ERC-20 tokens can never be redeemed for real NEP-141 tokens. The buyers suffer a direct, irreversible loss equal to `N × f` tokens.

---

### Likelihood Explanation

**High.**

1. `deploy_erc20_token` is a permissionless NEAR call — any account can register any NEP-141 token.
2. Deploying a fee-on-transfer NEP-141 on NEAR requires only standard NEAR contract deployment skills.
3. The entire attack is self-contained: deploy token → register ERC-20 mirror → bridge → sell unbacked ERC-20 → exit with real NEP-141.
4. No privileged access, no oracle, no governance capture is required.

---

### Recommendation

1. **Verify actual balance change.** Before and after the NEP-141 transfer, read Aurora's own NEP-141 balance (via a cross-contract view call or by storing the pre-transfer balance). Mint ERC-20 tokens equal to the *observed* balance delta, not `args.amount`.

2. **Alternatively, whitelist bridgeable NEP-141 tokens.** Add an admin-controlled allowlist to `deploy_erc20_token` so that only audited, standard-compliant NEP-141 tokens can obtain an ERC-20 mirror.

3. **Document the assumption.** At minimum, add an explicit invariant check or comment that fee-on-transfer NEP-141 tokens are unsupported, so integrators are warned.

---

### Proof of Concept

**Setup:**
- Deploy a NEAR NEP-141 contract `fee_token.near` that deducts a 10 % fee on every `ft_transfer_call` (i.e., transfers `0.9 × amount` to the receiver but calls `ft_on_transfer` with the full `amount`).

**Steps:**

1. **Register the ERC-20 mirror** (permissionless):
   ```
   aurora.call("deploy_erc20_token", borsh(fee_token.near))
   ```
   Aurora deploys `EvmErc20` at some address `ERC20_ADDR`.

2. **Bridge 1 000 tokens:**
   ```
   fee_token.near.call("ft_transfer_call",
       receiver_id = "aurora",
       amount      = "1000",
       msg         = hex(ATTACKER_EVM_ADDRESS))
   ```
   - `fee_token.near` transfers 900 tokens to Aurora, keeps 100 as fee.
   - `fee_token.near` calls `aurora.ft_on_transfer(sender=attacker, amount=1000, msg=...)`.
   - `receive_erc20_tokens` reads `args.amount = 1000` and mints **1 000 ERC-20** tokens to `ATTACKER_EVM_ADDRESS`.
   - Aurora's actual NEP-141 balance: **900**.

3. **Sell 1 000 ERC-20 tokens** on an Aurora DEX to victim `V` for fair-value consideration.

4. **Victim attempts to exit:**
   ```solidity
   EvmErc20(ERC20_ADDR).withdrawToNear(recipient_bytes, 1000);
   ```
   - Burns 1 000 ERC-20 tokens.
   - `ExitToNear` precompile schedules `ft_transfer(receiver=V, amount=1000)` on `fee_token.near`.
   - Aurora only holds 900 NEP-141 tokens → `ft_transfer` fails.
   - With `error_refund` feature: 1 000 ERC-20 re-minted (victim stuck in loop).
   - Without `error_refund` feature: 1 000 ERC-20 permanently burned, victim loses everything.

5. **Net result:** Attacker received full sale proceeds; victim holds worthless or permanently frozen ERC-20 tokens. Aurora's NEP-141 reserve is permanently 100 tokens short of the outstanding ERC-20 supply.