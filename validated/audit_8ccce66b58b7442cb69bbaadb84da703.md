### Title
Tokens received by the controller outside declared collateral/refund sets are permanently locked — no sweep or recovery path exists - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary

The controller only ever moves tokens it explicitly accounts for: measured collateral deltas become supply deposits, and only assets listed in `refund_assets` are returned to the caller via `refund_listed_assets` (contracts/controller/src/strategies/flash_position.rs:372-384). Any token balance the controller holds that was not declared in `collaterals` or `refund_assets` — whether sent by the flash receiver during `execute_flash_position`, pushed by a swap route leg in `multiply`/`swap_debt`/`swap_collateral`/`repay_debt_with_collateral`, or transferred directly to the controller address — is never credited, never refunded, and there is no sweep/rescue entrypoint on the controller. This is the direct analog of the report's "collateral transferred to a contract with no withdrawal path": the tokens sit in the controller balance permanently.

### Finding Description

In `process_flash_position` the controller snapshots balances of only the declared `collaterals` assets and `refund_assets` before invoking the receiver, then after the callback it deposits the declared collateral deltas and refunds only the declared refund assets (flash_position.rs:120-148). `validate_refund_assets` restricts refund assets to tokens listed in the account's spoke and disjoint from collaterals (flash_position.rs:240-255), and enforces a `max_supply_positions` bound — but nothing forces a receiver to declare every asset it will return. The same measured-delta-only pattern is used across the other strategy entrypoints (`payments.rs` `balance_delta_since` / `refund_controller_balance_delta`), so undeclared callback receipts are ignored everywhere. The public controller surface (lib.rs) contains no token-recovery or sweep function; the endpoint reference states "Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint" (docs/reference/endpoints.md:86). Since Soroban SAC `transfer` to a contract address requires no receiver hook, there is no equivalent of `onERC721Received` to reject the inbound transfer — the tokens are simply stranded.

### Impact Explanation

Permanent freezing of funds. Any token delivered to the controller outside the declared collateral/refund set is irrevocably stuck: it cannot be claimed as revenue (`claim_revenue` forwards only the controller's measured receipts for listed market assets), cannot be seized (seizures debit account positions, not controller balances), and cannot be withdrawn because no privileged or unprivileged endpoint transfers arbitrary controller-held tokens. A flash-position receiver that returns a swapped asset not present in `refund_assets` (e.g., the swap produces a token the integrator forgot to declare, or the refund list overflows `max_supply_positions`) loses those funds entirely. Direct donations to the controller address strand the same way.

### Likelihood Explanation

Medium. The receiver contract is deployed by the caller, so the primary loss is to the integrating user rather than an external victim — but the contract gives no error or rejection signal, the failure is silent, and the `max_supply_positions` bound on `refund_assets` (typically small) means a legitimate multi-asset unwind can exceed the declarable set. Direct transfers to the controller also require no privilege and are easy to make accidentally on Stellar. There is no way for an attacker to force third-party funds into the controller, which keeps this at Medium rather than High.

### Recommendation

- Add a guarded sweep/rescue entrypoint (e.g., governance-authorized `rescue_token(asset, to, amount)`), or
- Revert `process_flash_position` and other strategy flows when the post-callback controller balance of any non-declared listed asset increased, forcing callers to declare all expected receipts, or
- Extend the refund mechanism to iterate over all listed spoke assets whose controller balance increased, rather than only the caller-supplied `refund_assets` list.

### Proof of Concept

Conceptual trace (Soroban test):

1. Supply collateral and open a normal position so `flash_position` is callable on a flashloanable debt market (per `flash_position.rs:87-91`).
2. Deploy a Wasm receiver implementing `execute_flash_position` that, inside the callback, transfers both the declared collateral token *and* an extra listed token `X` (not in `collaterals`, not in `refund_assets`) to the controller address.
3. Call `flash_position(caller, account_id, spoke_id, Multiply, debt=(hub, DEBT), amount, receiver, data, collaterals=[(hub,COLL), min] , refund_assets=[ ])` — `refund_assets` deliberately excludes `X`.
4. The call succeeds: `collect_collateral_deposits` only measures declared collateral deltas (flash_position.rs:325-352) and `refund_listed_assets` only iterates `refund_assets` (flash_position.rs:378-383), so `X`'s balance delta is ignored.
5. Assert `token::Client::new(env, &X).balance(&controller) == amount_X` and enumerate the controller ABI — no endpoint can move `X`. The tokens are locked permanently, mirroring the StabilityPool NFT lock in the source report.