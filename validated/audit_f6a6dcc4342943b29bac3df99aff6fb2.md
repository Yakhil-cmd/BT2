[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** pox-locking/src/pox_2.rs (L31-56)
```rust
/// is a PoX-2 function call read only?
pub fn is_read_only(func_name: &str) -> bool {
    "get-pox-rejection" == func_name
        || "is-pox-active" == func_name
        || "burn-height-to-reward-cycle" == func_name
        || "reward-cycle-to-burn-height" == func_name
        || "current-pox-reward-cycle" == func_name
        || "get-stacker-info" == func_name
        || "get-check-delegation" == func_name
        || "get-reward-set-size" == func_name
        || "next-cycle-rejection-votes" == func_name
        || "get-total-ustx-stacked" == func_name
        || "get-reward-set-pox-address" == func_name
        || "get-stacking-minimum" == func_name
        || "check-pox-addr-version" == func_name
        || "check-pox-addr-hashbytes" == func_name
        || "check-pox-lock-period" == func_name
        || "can-stack-stx" == func_name
        || "minimal-can-stack-stx" == func_name
        || "get-pox-info" == func_name
        || "get-delegation-info" == func_name
        || "get-allowance-contract-callers" == func_name
        || "get-num-reward-set-pox-addresses" == func_name
        || "get-partial-stacked-by-cycle" == func_name
        || "get-total-pox-rejection" == func_name
}
```

**File:** pox-locking/src/pox_5.rs (L34-60)
```rust
#[derive(Debug)]
enum ParsedStakeResult {
    Ok {
        staker: PrincipalData,
        amount_ustx: u128,
        unlock_burn_height: u64,
    },
    ContractErr,
}

/// Parse the returned value from PoX-5 `stake`, `stake-update`,
/// `register-for-bond`, and `unstake`. These functions return
/// `(ok { staker, amount-ustx, unlock-burn-height, ... })` on success and
/// `(err <code>)` on failure.
///
/// Returns `Err(LockingError::PoxMalformedResponse(...))` if the response
/// shape doesn't match the expected pox-5 contract — that's an invariant
/// violation, not a user-level failure, so callers should propagate it
/// rather than silently no-op.
fn parse_pox_stake_result(result: &Value) -> Result<ParsedStakeResult, LockingError> {
    let response = result
        .clone()
        .expect_result()
        .map_err(|e| LockingError::PoxMalformedResponse(format!("not a response: {e:?}")))?;
    match response {
        Ok(res) => {
            let tuple_data = res.expect_tuple().map_err(|e| {
```
