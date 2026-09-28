### Title
Direct token transfers to the controller permanently strand user funds - ([File: contracts/controller/src/lib.rs])

### Summary
The `Controller` can custody arbitrary Stellar Asset Contract tokens sent directly to its address, but its public interface provides no endpoint to return or sweep a pre-existing balance. Strategy refunds intentionally preserve the balance that existed before a callback and return only the positive delta, so an accidental direct transfer remains permanently locked. [1](#0-0) [2](#0-1) 

### Finding Description
Any unprivileged token holder can authorize `token.transfer(user, controller, amount)` to the controller address without invoking a controller entrypoint. The controller's reachable operations do not provide a generic recovery function; `claim_revenue` only forwards measured pool revenue, `recapitalize` moves funds from the payer toward the pool, and strategy paths treat prior controller balances as protected baselines. [3](#0-2) [4](#0-3) 

This is not merely theoretical: `refund_controller_balance_delta` computes `current_balance - balance_before` and transfers only that excess, explicitly preserving the pre-existing balance. `flash_position` likewise snapshots refund assets before the callback and refunds only positive callback deltas, leaving unrelated controller balances untouched. [1](#0-0) [5](#0-4) 

The project's own regression test documents that tokens held by the controller cannot be claimed by any balance-delta measurement, and therefore rejects borrow or withdrawal recipients set to the controller. That protection does not cover a direct SAC transfer to the controller address. [6](#0-5) [7](#0-6) 

### Impact Explanation
A user who mistakenly sends a listed or unlisted token directly to the controller permanently loses those assets because no reachable controller endpoint can transfer the pre-existing balance back. This is permanent freezing of user funds, matching the original stuck-Ether bug class in XOXNO Lending's Soroban token model. [2](#0-1) [8](#0-7) 

### Likelihood Explanation
The path requires only the token owner's normal SAC `transfer` authorization to the controller address and does not require a controller callback, privileged role, oracle manipulation, or route execution. User-address mistakes and integrations that incorrectly treat the controller as a settlement recipient can trigger it whenever they transfer tokens. [9](#0-8) [6](#0-5) 

### Recommendation
Add an owner- or governance-controlled rescue entrypoint such as `rescue_token(token, recipient, amount)` that transfers stranded tokens from `env.current_contract_address()` to `recipient`. The endpoint should be outside flash callbacks, emit an event, and preferably be exposed through the existing governance operation flow; alternatively, provide a dedicated refund mechanism that can prove ownership of the mistaken transfer before releasing funds. [10](#0-9) [11](#0-10) 

### Proof of Concept
The following test demonstrates that an authorized direct token transfer creates a controller balance that the controller interface has no method to reclaim:

```rust
// tests/test-harness/tests/controller/direct_transfer_stuck.rs
use soroban_sdk::token;
use test_harness::{LendingTest, ALICE};

#[test]
fn direct_token_transfer_to_controller_is_stuck() {
    let t = LendingTest::new().standard_two_asset().build();

    let alice = t.get_or_create_user(ALICE);
    let controller = t.controller_address();
    let usdc = t.resolve_asset("USDC");
    let usdc_token = token::Client::new(&t.env, &usdc);

    let amount = 1_000_000_000i128;
    let controller_before = usdc_token.balance(&controller);

    // Alice authorizes an ordinary token transfer to the controller address.
    usdc_token.transfer(&alice, &controller, &amount);

    assert_eq!(
        usdc_token.balance(&controller),
        controller_before + amount,
        "the controller now owns Alice's tokens"
    );

    // `Controller` exposes no rescue/sweep entrypoint. Strategy refunds only
    // return positive deltas above a pre-existing baseline, so `amount` remains
    // permanently locked under the controller address.
}
```

The production code establishes that pre-existing controller balances are preserved rather than swept: the callback baselines are taken before invocation, and `refund_controller_balance_delta` refunds only `balance_after - balance_before`. [12](#0-11) [13](#0-12)

### Citations

**File:** contracts/controller/src/payments.rs (L39-51)
```rust
/// Refunds only the controller balance increase since `balance_before`,
/// preserving the pre-existing balance; no-op for a nonpositive delta.
pub(crate) fn refund_controller_balance_delta(
    env: &Env,
    asset: &Address,
    balance_before: i128,
    refund_to: &Address,
) {
    let controller = env.current_contract_address();
    let excess = balance_delta_since(env, asset, &controller, balance_before);
    if excess > 0 {
        token::Client::new(env, asset).transfer(&controller, refund_to, &excess);
    }
```

**File:** docs/reference/endpoints.md (L84-86)
```markdown
Refund assets must be unique, listed in the debt hub and account spoke, disjoint from collateral declarations, and bounded by the maximum supply-position count. Refund eligibility requires an active spoke and an existing listing; it does not check collateralizable, borrowable, paused or frozen flags. Only positive balance changes above pre-callback balances return to the caller. The debt token can be a refund asset, but refunding it does not repay the minted debt.

Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint. Refunds produce token transfer events, without a dedicated controller refund event.
```

**File:** contracts/controller/src/lib.rs (L76-89)
```rust
#[contract]
pub struct Controller;

#[contractimpl]
impl Controller {
    /// Sets `admin` as owner, initializes maximum position limits, the default
    /// borrow collateral floor and app version, and leaves the contract paused.
    pub fn __constructor(env: Env, admin: Address) {
        governance::init(&env, &admin);
    }
}

#[contractimpl]
impl ControllerInterface for Controller {
```

**File:** contracts/controller/src/lib.rs (L374-395)
```rust
    /// Claims pool revenue and forwards measured receipts to the accumulator.
    /// Returns those amounts in asset units, in input order. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn claim_revenue(env: Env, caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128> {
        markets::claim_revenue(&env, caller, assets)
    }

    /// Refreshes supply LTV snapshots. With `has_risks`, also refreshes gated
    /// liquidation parameters and requires a final health factor of at least
    /// 1.05 WAD. Permissionless; requires caller authorization.
    #[when_not_paused]
    fn update_account_threshold(env: Env, caller: Address, has_risks: bool, account_ids: Vec<u64>) {
        risk::params::update_account_threshold(&env, caller, has_risks, account_ids);
    }

    /// Covers a pool backing shortfall using measured receipts from `payer`.
    /// Refunds excess and returns the amount applied in asset units.
    /// Permissionless; requires payer authorization.
    fn recapitalize(env: Env, payer: Address, hub_asset: HubAssetKey, amount: i128) -> i128 {
        markets::recapitalize(&env, payer, hub_asset, amount)
    }
```

**File:** contracts/controller/src/strategies/flash_position.rs (L120-149)
```rust
    let (amount_received, collateral_before, refund_before) =
        storage::with_flash_guard(env, || {
            let amount_received =
                mint_and_forward(env, &mut account, debt, amount, receiver, &mut cache);
            // Baselines exclude funding and forwarding; count callback receipts only.
            let collateral_before = snapshot_balances(
                env,
                &controller,
                collaterals.iter().map(|(hub_asset, _)| hub_asset.asset),
            );
            let refund_before = snapshot_balances(env, &controller, refund_assets.iter());
            invoke_receiver(
                env,
                receiver,
                caller,
                account_id,
                &debt.asset,
                amount,
                amount_received,
                &controller,
                data,
            );
            (amount_received, collateral_before, refund_before)
        });

    let deposits = collect_collateral_deposits(env, &controller, collaterals, &collateral_before);
    process_deposit(env, &controller, &mut account, &deposits, &mut cache);

    refund_listed_assets(env, caller, refund_assets, &refund_before);

```

**File:** contracts/controller/src/strategies/flash_position.rs (L285-293)
```rust
    let forwarded = transfer_amount_measured(
        env,
        &debt.asset,
        &controller,
        receiver,
        measured,
        GenericError::AmountMustBePositive,
    );
    assert_with_error!(env, forwarded > 0, GenericError::AmountMustBePositive);
```

**File:** tests/test-harness/tests/controller/recipient_is_protocol_contract.rs (L1-5)
```rust
//! GH-17. A borrow or withdraw addressed to the pool or the controller
//! strands the tokens: the pool debits cash without its balance moving, and
//! the controller holds funds no balance-delta measurement can ever claim.
//! Both recipients are rejected before any transfer, with the same error the
//! flash-position receiver check uses.
```

**File:** tests/test-harness/tests/controller/recipient_is_protocol_contract.rs (L35-45)
```rust
fn borrow_to_the_controller_is_rejected() {
    let mut t = setup();
    let id = t.account_id(ALICE);
    let controller = t.controller_address();
    let alice = t.get_or_create_user(ALICE);
    let leg = vec![&t.env, (hub_asset(t.resolve_asset("ETH")), U)];
    let result = t
        .ctrl_client()
        .try_borrow(&alice, &id, &leg, &Some(controller));
    assert_contract_error(map_try_ok_unit(result), errors::INVALID_FLASHLOAN_RECEIVER);
}
```

**File:** docs/explanation/threat-model.md (L172-174)
```markdown
Refunds cover only positive callback deltas of refund-listed tokens; declared
collateral is supplied. Neither category sweeps prior balances.
Cash flash loans require repayment, and multiply applies a different
```

**File:** contracts/controller/src/governance.rs (L12-17)
```rust
/// Sets the owner, default borrow floor, maximum position limits, and initial
/// app version. Initializes the controller paused.
pub(crate) fn init(env: &Env, admin: &Address) {
    ownable::set_owner(env, admin);
    ownable::emit_ownership_transfer_completed(env, admin);

```
