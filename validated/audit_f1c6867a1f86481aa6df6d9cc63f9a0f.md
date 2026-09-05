[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** pox-locking/src/pox_5.rs (L53-119)
```rust
fn parse_pox_stake_result(result: &Value) -> Result<ParsedStakeResult, LockingError> {
    let response = result
        .clone()
        .expect_result()
        .map_err(|e| LockingError::PoxMalformedResponse(format!("not a response: {e:?}")))?;
    match response {
        Ok(res) => {
            let tuple_data = res.expect_tuple().map_err(|e| {
                LockingError::PoxMalformedResponse(format!("ok payload not a tuple: {e:?}"))
            })?;
            let staker = tuple_data
                .get("staker")
                .map_err(|_| LockingError::PoxMalformedResponse("missing 'staker'".into()))?
                .to_owned()
                .expect_principal()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'staker' is not a principal: {e:?}"
                    ))
                })?;

            let amount_ustx = tuple_data
                .get("amount-ustx")
                .map_err(|_| LockingError::PoxMalformedResponse("missing 'amount-ustx'".into()))?
                .to_owned()
                .expect_u128()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'amount-ustx' is not a uint: {e:?}"
                    ))
                })?;

            let unlock_burn_height_u128 = tuple_data
                .get("unlock-burn-height")
                .map_err(|_| {
                    LockingError::PoxMalformedResponse("missing 'unlock-burn-height'".into())
                })?
                .to_owned()
                .expect_u128()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'unlock-burn-height' is not a uint: {e:?}"
                    ))
                })?;
            let unlock_burn_height: u64 = unlock_burn_height_u128.try_into().map_err(|_| {
                LockingError::PoxMalformedResponse(format!(
                    "'unlock-burn-height' overflows u64: {unlock_burn_height_u128}"
                ))
            })?;

            Ok(ParsedStakeResult::Ok {
                staker,
                amount_ustx,
                unlock_burn_height,
            })
        }
        Err(e) => {
            // Validate the err payload shape — pox-5 is typed
            // `(response ... uint)`, so a non-uint here means the response
            // is malformed and should surface as such.
            e.expect_u128().map_err(|err| {
                LockingError::PoxMalformedResponse(format!("err payload not a uint: {err:?}"))
            })?;
            Ok(ParsedStakeResult::ContractErr)
        }
    }
}
```

**File:** pox-locking/src/pox_5.rs (L196-231)
```rust
/// Reschedule a pox-5 STX lock to unlock at `unlock_burn_height`. Used by
/// `unstake`, which moves the unlock to the start of the next reward
/// cycle. The locked amount is unchanged. Does NOT touch the account
/// nonce.
///
/// # Errors
/// - Returns Error::PoxUnstakeNotLocked if this function was called on an account
///   which isn't locked. This *should* have been checked by the PoX v5 contract,
///   so this should surface in a panic.
pub fn pox_unstake_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
) -> Result<(), LockingError> {
    if unlock_burn_height == 0 {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxUnstakeNotLocked);
    }

    snapshot.update_unlock_v5(unlock_burn_height)?;

    debug!(
        "PoX v5 unstake scheduled";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
}
```
