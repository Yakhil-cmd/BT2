Audit Report

## Title
Unprivileged Caller Can Grief Any Account's `update_balance` by Specifying Arbitrary `owner` - (File: rs/bitcoin/ckbtc/minter/src/updates/update_balance.rs)

## Summary
The `update_balance` endpoint resolves the target account using `args.owner.unwrap_or(caller)` without verifying that `args.owner`, when supplied, equals the caller. The per-account concurrent-execution guard is keyed on this resolved account, so any unprivileged caller can acquire and hold the guard for an arbitrary victim's account across multiple async round-trips, causing the victim's own `update_balance` calls to return `AlreadyProcessing` for the duration.

## Finding Description
In `update_balance`, the guard account is constructed as:

```rust
let caller_account = Account {
    owner: args.owner.unwrap_or(caller),
    subaccount: args.subaccount,
};
let _guard = balance_update_guard(caller_account)?;
``` [1](#0-0) 

There is no assertion that `args.owner == Some(caller)`. The `balance_update_guard` calls `Guard::new`, which inserts the account into `state.update_balance_accounts` and returns `Err(GuardError::AlreadyProcessing)` if it is already present: [2](#0-1) 

The guard is held for the entire async lifetime of `update_balance`, which includes at least one cross-canister `get_utxos` call to the Bitcoin canister and potentially a second `get_utxos` call (with zero confirmations) when no new UTXOs are found: [3](#0-2) [4](#0-3) 

The `update_balance` DID interface explicitly exposes `owner` as an optional public parameter: [5](#0-4) 

**Exploit flow:**
1. Attacker submits `update_balance({ owner = opt V; subaccount = null })`. Guard for `Account { owner: V, subaccount: None }` is acquired and held across async `get_utxos` calls.
2. Victim V submits `update_balance({ owner = null; subaccount = null })`. Resolved account is identical. Guard check finds it present → returns `Err(AlreadyProcessing)`.
3. Attacker's call completes (returns `NoNewUtxos` if V's UTXOs are unconfirmed). Guard is dropped.
4. Attacker immediately re-submits. Repeat indefinitely.

Secondary impact: with `MAX_CONCURRENT = 100`, an attacker using 100 distinct subaccounts can simultaneously exhaust the global concurrent-request budget, causing `TooManyConcurrentRequests` for all users: [6](#0-5) [7](#0-6) 

## Impact Explanation
This is an application-level DoS against ckBTC minting — a financial integration explicitly in scope. A victim who has deposited BTC cannot mint ckBTC for as long as the attacker sustains the loop. This matches the allowed High impact: **"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS"** and **"Significant Chain Fusion, ck-token, ledger... security impact with concrete user or protocol harm."** Severity: **High ($2,000–$10,000)**.

## Likelihood Explanation
The attack requires only the ability to send ingress messages to the ckBTC minter — no tokens, no special role, no prior relationship with the victim. The victim's principal is derivable from the public `get_btc_address` query endpoint. Per-call cost is the standard IC ingress fee plus cycles for `get_utxos`. The attacker must re-submit after each call completes, but the cost per iteration is low and the loop is trivially automated.

## Recommendation
Add a caller-authorization check before constructing `caller_account`: if `args.owner` is `Some(p)` and `p != caller`, reject the call (or require the caller to be a pre-authorized delegate). The minimal fix:

```rust
let owner = args.owner.unwrap_or(caller);
if owner != caller {
    return Err(UpdateBalanceError::GenericError {
        error_message: "caller must match owner".to_string(),
        error_code: ...,
    });
}
```

Alternatively, key the guard on the **caller** principal rather than the resolved owner, so that an attacker's guard never blocks the victim's guard slot.

## Proof of Concept
1. Initialize a local PocketIC replica with the ckBTC minter canister.
2. Create two identities: victim `V` and attacker `A`.
3. From `A`, call `update_balance({ owner = opt V; subaccount = null })` and capture the in-flight call (do not await).
4. From `V`, call `update_balance({ owner = null; subaccount = null })` while step 3 is in-flight.
5. Assert that V's call returns `Err(UpdateBalanceError::AlreadyProcessing)`.
6. Await A's call; assert it returns `NoNewUtxos`.
7. Repeat steps 3–6 in a loop to demonstrate sustained DoS.

The existing unit test in `guard.rs` (`guard_limits_one_account`) already demonstrates the `AlreadyProcessing` behavior for the same account — the PoC extends this to cross-caller account targeting. [8](#0-7)

### Citations

**File:** rs/bitcoin/ckbtc/minter/src/updates/update_balance.rs (L164-168)
```rust
    let caller_account = Account {
        owner: args.owner.unwrap_or(caller),
        subaccount: args.subaccount,
    };
    let _guard = balance_update_guard(caller_account)?;
```

**File:** rs/bitcoin/ckbtc/minter/src/updates/update_balance.rs (L175-183)
```rust
    let utxos = get_utxos(
        btc_network,
        &address,
        min_confirmations,
        CallSource::Client,
        runtime,
    )
    .await?
    .utxos;
```

**File:** rs/bitcoin/ckbtc/minter/src/updates/update_balance.rs (L225-236)
```rust
        let GetUtxosResponse {
            tip_height,
            mut utxos,
            ..
        } = get_utxos(
            btc_network,
            &address,
            /*min_confirmations=*/ 0,
            CallSource::Client,
            runtime,
        )
        .await?;
```

**File:** rs/bitcoin/ckbtc/minter/src/guard.rs (L6-6)
```rust
const MAX_CONCURRENT: usize = 100;
```

**File:** rs/bitcoin/ckbtc/minter/src/guard.rs (L45-59)
```rust
    pub fn new(account: Account) -> Result<Self, GuardError> {
        mutate_state(|s| {
            let accounts = PR::pending_requests(s);
            if accounts.contains(&account) {
                return Err(GuardError::AlreadyProcessing);
            }
            if accounts.len() >= MAX_CONCURRENT {
                return Err(GuardError::TooManyConcurrentRequests);
            }
            accounts.insert(account);
            Ok(Self {
                account,
                _marker: PhantomData,
            })
        })
```

**File:** rs/bitcoin/ckbtc/minter/src/guard.rs (L123-138)
```rust
    #[test]
    fn guard_limits_one_account() {
        // test that two guards for the same principal cannot exist in the same block
        // and that a guard is properly dropped at end of the block

        init(init_args(), &IC_CANISTER_RUNTIME);
        // a1 and a2 are effectively the same Account
        let a1 = test_account(0, None);
        let a2 = test_account(0, Some(0));
        {
            let _guard = balance_update_guard(a1).unwrap();
            let res = balance_update_guard(a2).err();
            assert_eq!(res, Some(GuardError::AlreadyProcessing));
        }
        let _ = balance_update_guard(a1).unwrap();
    }
```

**File:** rs/bitcoin/ckbtc/minter/ckbtc_minter.did (L704-704)
```text
    update_balance : (record { owner: opt principal; subaccount : opt blob }) -> (variant { Ok : vec UtxoStatus; Err : UpdateBalanceError });
```
