Target: StackStxOp::check num_cycles upper bound vs current-pox-reward-cycle offset math in create_event_info_data_code's 'stack-stx' unlock-burn-height formula (pox-locking/src/events.rs lines 124-173: '(+ (current-pox-reward-cycle) u1 lock_period)'). Attacker action: exploit the missing return Err noted above (num_cycles==0 or >POX_MAX_NUM_CYCLES only warns) by submitting num_cycles=0 specifically, then trace whether reward-cycle-to-burn-height(current-cycle+1+0) computes an unlock height EQUAL TO OR BEFORE the start-burn-height, i.e., an already-elapsed/immediate unlock. Preconditions: attacker's own PreStxOp/StackStxOp with num_cycles=0, positive stacked_ustx. Call sequence: check() lets num_cycles=0 through; if the op still reaches pox_lock_v5 with an unlock_height computed from num_cycles=0, the resulting unlock_burn_height could equal the CURRENT height or earlier. Equality broken: SINGLE UNLOCK - 'value unlocks once, at the committed height, only for its owner' requires unlock_height to be in the future relative to lock time; pox_lock_v5 does check 'unlock_burn_height == 0 -> Err(PoxInvalidUnlockHeight)' but does NOT check unlock_burn_height <= current burn height, so a num_cycles=0-derived unlock height at or before 'now' would let the attacker's own STX be instantly re-spendable, i.e., a lock that grants no real lock duration despite emitting a lock event and consuming a reward-cycle slot. Scoped impact: Critical - an UNBACKED

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L200-221)
```rust
        let stacked_ustx = parse_u128_from_be(data.get(0..16)?).unwrap();
        let num_cycles = *data.get(16)?;

        let mut signer_key: Option<StacksPublicKeyBuffer> = None;
        let mut max_amount: Option<u128> = None;
        let mut auth_id: Option<u32> = None;

        if data.len() >= 50 {
            signer_key = Some(StacksPublicKeyBuffer::from(data.get(17..50)?));
        }
        if data.len() >= 66 {
            let Some(amt) = parse_u128_from_be(data.get(50..66)?) else {
                return None;
            };
            max_amount = Some(amt);
        }
        if data.len() >= 70 {
            let Some(id) = parse_u32_from_be(data.get(66..70)?) else {
                return None;
            };
            auth_id = Some(id);
        }
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L232-247)
```rust
    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!(
