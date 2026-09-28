### Title
Tokens transferred directly to the pool are permanently locked — no sweep or rescue path exists - (File: contracts/pool/src/cache/cash.rs / contracts/pool/src/ops/revenue.rs)

### Summary
The analog of the reported "unreachable payout path locks ERC20 tokens" is XOXNO Lending's pool custody model. The pool tracks `cash` as a pure bookkeeping number and never reconciles it against `token.balance()` except inside `flash_loan`. Every outbound path (`withdraw`, `borrow`, `claim_revenue`, `recapitalize` refund) is capped by share books or tracked cash, and neither the pool nor the controller exposes a permissionless or governance-reachable function that can release balance above the books. Any tokens sent directly to a pool address (or the controller address) are locked forever.

### Finding Description
- `cash` is a book entry: "Tracked cash is a separate reserve balance that incidental token donations do not increase" (`docs/reference/formulas.md`), and "Direct donations do not rewrite those books" (`docs/explanation/threat-model.md`). `supply`, `repay`, and `recapitalize` credit cash only on the controller's inbound measurement; nothing ever credits an unbooked donation.
- Outbound legs are all book-capped: `withdraw`/`borrow` debit tracked cash and transfer at most the share-valued amount; `claim_revenue` pays `min(cash, floor(revenue_value))` to the pool owner (`contracts/pool/src/ops/revenue.rs:22-35`); `recapitalize` refunds at most the excess over the backing shortfall, so it cannot drain a donation that sits below or beside the books.
- There is no `sweep`/`skim`/`rescue` entrypoint in `contracts/pool` (no matches), and the controller surface documented in `docs/reference/endpoints.md` contains no token-recovery function either — the GH-17 fix deliberately rejects `borrow`/`withdraw` addressed to the pool or controller because "the controller holds funds no balance-delta measurement can ever claim" (`tests/test-harness/tests/controller/recipient_is_protocol_contract.rs`).
- Governance cannot help: the pool's only caller is the controller that deployed it (`deploy_v2` sets the controller as owner; pool README "Trust"), and no governance operation reaches pool-held tokens outside the fixed ABI.
- Reachability by an unprivileged address is trivial: `token.transfer(sender, pool, amount)` — an explicitly allowed path in scope.

### Impact Explanation
Permanent freezing of funds. Tokens pushed to a pool (or controller) address become unclaimable by anyone — including the sender, suppliers, liquidators, the accumulator, and governance — because every exit is bounded by `cash`/share books and no entrypoint releases the excess. This mirrors the original report exactly: the payout machinery exists but has no reachable path for the stranded balance.

### Likelihood Explanation
Medium. It requires an erroneous or incidental direct transfer rather than deliberate protocol use — entrypoints reject protocol recipients precisely because such stranding is recognized — but it needs only a single permissionless `transfer`, and accrued stray balances (e.g., fee-on-transfer remainders at the controller, venue reward pushes described in the threat model) accumulate the same way.

### Recommendation
Add a bounded recovery path for excess custody, e.g. a controller-initiated `skim` that transfers `token.balance(pool) - cash` of unbooked surplus to the accumulator, or a governance operation that sweeps tokens not backing the books, while preserving the `flash_loan` strict-balance invariant (either exclude flash-loanable markets or update `terms` expectations accordingly).

### Proof of Concept
1. Deploy hub + market; ALICE supplies 10,000 USDC via `controller.supply` (pool `cash` = 10,000·u, `balance` = 10,000·u).
2. MALLORY (or ALICE by mistake) calls `usdc.transfer(mallory, pool, 500·u)` directly on the SAC.
3. Observe `token.balance(pool) = 10,500·u` while `state.cash` remains 10,000·u.
4. Attempt every outbound path: `withdraw` of full supply returns at most the share-valued claim; `claim_revenue` pays only `min(cash, floor(revenue_value))`; `recapitalize` refunds only the amount exceeding the shortfall. The 500·u residue is unreachable by any ABI call — permanently locked.