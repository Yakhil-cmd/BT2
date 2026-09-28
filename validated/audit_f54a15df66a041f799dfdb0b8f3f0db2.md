### Title
Malicious swap venue can ride the caller authorization tree and drain unrelated wallet tokens - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
Controller swap strategies pass caller-supplied route bytes to the configured router while the caller has authorized the outer strategy call. Because route-selected venue contracts execute as nested calls beneath that authorization, a malicious venue can request a `token.transfer(victim, attacker, amount)` that simulation records as a child of the victim's strategy authorization. If the victim signs the simulated tree, the venue can move unrelated wallet tokens while the swap still returns a valid output and passes the controller's post-swap checks.

### Finding Description
The controller exposes several account strategies that accept opaque `swap` bytes and invoke the configured swap router, including `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply`. In `swap_tokens`, the controller snapshots its input/output balances, grants the router one exact controller-token transfer, calls `execute_strategy`, and only validates the router's measured spend and positive output (`contracts/controller/src/strategies/swap.rs:29-54`).

That settlement model constrains what the router may do with the controller's input token, but it does not constrain Soroban authorization requests made by contracts deeper in the route. The router executes pool/venue addresses carried inside the route payload. A malicious venue called beneath the strategy can invoke any token contract's `transfer` with the victim as `from`. Since the victim already authorized the root strategy call, the host records that nested token transfer as a child invocation and accepts it if the submitted signed tree contains it.

The repository's adversarial test demonstrates this exact behavior through `swap_collateral`: a route calls an unlisted rogue pool, the pool calls `wallet_token.transfer(alice, attacker, wallet_balance)`, simulation records that transfer under Alice's `swap_collateral` authorization, and signing that tree drains the unrelated token while the expected swap output is still credited (`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs:194-269`). The threat model also documents that route-selected code is not allowlisted and that a signed child token transfer is not bounded by route minimums or the final risk gate (`docs/explanation/threat-model.md:154-165`).

### Impact Explanation
Theft of user funds. The malicious venue can transfer any token balance held by the caller, including assets unrelated to the lending position and assets that were never supplied to the protocol. The strategy can still deliver a fair or profitable-looking swap output, so the theft is hidden inside an otherwise successful transaction.

The attack does not steal protocol reserves directly and does not bypass the controller's measured input/output checks. Instead, it escapes the intended security boundary by executing attacker-selected contract code under the victim's broader authorization tree.

### Likelihood Explanation
Likelihood depends on getting a victim to submit a malicious route and sign the expanded authorization tree. The attacker can provide an attractive quote or poisoned route bytes, and the swap itself can still satisfy the declared minimum output and final account risk checks. A wallet or client that faithfully shows the authorization tree can prevent execution, but users commonly rely on simulation output and may not decode venue addresses or nested token transfers.

No privileged role, leaked key, oracle manipulation, or contract upgrade is required. The attacker only needs to supply or induce a route containing a malicious venue address.

### Recommendation
Do not allow route payloads to name arbitrary executable venue contracts for controller-backed strategies. Restrict venue/pool addresses to a governance-approved registry, or route only through adapters that invoke fixed, allowlisted venue contracts. At minimum, decode and validate every route hop server-side and in the wallet, and reject any simulated authorization tree containing children other than the expected strategy input transfer.

Clients should display and enforce an exact authorization-tree policy: no additional token transfers, approvals, account operations, NFT operations, or calls to unrelated contracts beneath the strategy root. Longer term, isolate route execution so venue contracts cannot request authorization from the strategy caller.

### Proof of Concept
1. Victim owns a debt-free lending account with supplied `USDC` and also holds an unrelated `WALLET` token.
2. Attacker deploys `RoguePool` with stored parameters `(victim = Alice, wallet_token = WALLET, to = attacker, amount = WALLET_BALANCE)`.
3. Attacker constructs a `swap_collateral` call:

   ```text
   caller       = Alice
   account_id   = Alice's account
   collateral   = (hub_id, USDC)
   amount       = 5_000 USDC
   new_collateral = (hub_id, ETH)
   swap         = route bytes whose hop pool is RoguePool
   ```

4. Inside the nested route execution, `RoguePool.swap()` calls:

   ```rust
   token::Client::new(&env, &wallet_token)
       .transfer(&victim, &to, &amount);
   ```

5. Simulation records that token transfer as a child of Alice's `swap_collateral` authorization. If Alice signs the poisoned tree, the token transfer succeeds.
6. The router can simultaneously return the expected ETH output, causing the controller's measured-output and account-risk checks to pass.
7. Result: `WALLET` moves from Alice to the attacker, while the account's collateral swap appears successful.

The behavior is demonstrated by `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` and `enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer` in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`.