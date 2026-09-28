### Title
Permissionless `flash_loan` spends any WASM contract's standing pool allowance via `transfer_from`, charging unsolicited fees to a third party - ([File: contracts/pool/src/ops/flash.rs](contracts/pool/src/ops/flash.rs))

### Summary
The JOJO bug class is "an unprotected call lets the contract spend any user's existing token allowance." The same shape exists in `flash_loan`: an unprivileged caller picks `receiver`, and the pool ends the flow by calling `token.transfer_from(receiver → pool, amount + fee)` against whatever allowance that receiver previously granted the pool. The victim receiver never authorizes the call — only `caller` does — so anyone can repeatedly trigger flash loans "on behalf of" a contract that holds a standing approval, burning its balance as protocol fees.

### Finding Description
`Controller::flash_loan` requires only the `caller`'s authorization and forwards an arbitrary `receiver` address to `flash::apply` (`contracts/controller/src/lib.rs:171-180`).

Inside `apply`, the pool:

1. Pays `amount` of the asset to `receiver` (`flash.rs:60`).
2. Invokes `execute_flash_loan` on `receiver` (`flash.rs:150-163`) — `receiver` only needs to be a deployed WASM contract (`require_wasm_receiver`, `flash.rs:49`).
3. Pulls repayment by allowance: it asserts `asset.allowance(receiver, pool) >= total_repayment` and calls `asset.transfer_from(pool, receiver, pool, &total_repayment)` (`flash.rs:173-179`).

The critical point is step 3: repayment is collected from `receiver`'s **pre-existing allowance**, not from any authorization by `receiver` in this transaction. The receiver's `execute_flash_loan` callback is invoked via `env.invoke_contract` with no `require_auth` on the receiver's part and no signature check tying the victim to this loan. A receiver contract that keeps a persistent allowance to the pool (a natural pattern for contracts that take repeated flash loans, since the protocol documents "excess allowance is permitted" in ADR-0010) can be force-fed loans by anyone.

Each forced loan nets the victim `-fee` (it receives `amount`, then `amount + fee` is pulled from it). There is no cap on how many times this can be invoked in one transaction or across transactions: the attacker can loop `flash_loan` with the maximum `amount` the reserves and allowance permit until the victim's allowance or balance is exhausted. The drained value is booked as protocol revenue (`book_fee`, `flash.rs:125-128`), so the victim's funds are irreversibly converted into pool fees.

### Impact Explanation
Theft of user funds: any WASM contract holding a token allowance to the pool (exactly the setup the repayment mechanism relies on — ADR-0010 explicitly permits excess allowance) can have its balance forcibly consumed as flash-loan fees without ever authorizing the transaction. The loss is proportional to `flashloan_fee_bps × amount` per call and is repeatable to full allowance/balance depletion. The attacker need not profit directly for this to be a loss of user funds; alternatively an attacker controlling a beneficiary position in revenue claims indirectly captures the value.

### Likelihood Explanation
Likelihood is moderate. Preconditions: the victim must be a WASM contract (not a plain wallet) that has issued a non-expired `approve(receiver → pool)` covering `amount + fee`. This is precisely the integration pattern for programmatic flash-loan receivers, which commonly grant a generous or persistent allowance rather than exact-per-call approvals. Once such a contract exists, any unprivileged address can trigger the drain at any time with no race conditions, no oracle dependency, and no victim interaction. Limiting factors: the allowance must cover principal plus fee, and per-call extraction is bounded by the fee rate, so a full drain requires repeated calls.

### Recommendation
Authenticate the receiver to the loan. Options:

- Require `receiver.require_auth()` (or an equivalent invoker-auth check) inside `apply` before `collect_repayment`, so a third party cannot spend the receiver's allowance without its signature; or
- Restrict `receiver == caller` (or require the caller to be authorized by the receiver), matching the model used elsewhere where the paying party authorizes the pull; or
- Repay via the callback's measured token transfer to the pool instead of `transfer_from`, so repayment is an explicit action by the receiver rather than a pull on a standing approval.

### Proof of Concept
1. Victim contract `V` implements `execute_flash_loan` and, as part of its normal integration, has executed `token.approve(V, pool, LARGE)` (per ADR-0010, excess allowance is allowed).
2. Attacker `A` calls `controller.flash_loan(caller=A, asset=X, amount=N, receiver=V, data=_)` where `N` is the largest amount the pool's cash reserves support.
3. `flash::apply` transfers `N` of X to `V`, invokes `V.execute_flash_loan` (no auth from V required — the call is a plain `invoke_contract`), then executes `token.transfer_from(pool, V, pool, N + fee)` consuming `V`'s allowance.
4. Net effect: `V` loses `fee` of X, booked as protocol revenue. `A` repeats the call until `V`'s allowance or balance is drained.
5. At no point does `V` authorize any of these transactions; the only auth on the call is `A`'s `caller.require_auth()` in the controller.

Relevant code: repayment pull at `contracts/pool/src/ops/flash.rs:166-179`, permissionless entrypoint at `contracts/controller/src/lib.rs:167-180`.