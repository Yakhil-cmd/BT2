### Title
Forged `DelegateStxOp.sender` via spoofed `PreStxOp.output` allows unauthorized STX delegation and reward redirection - (File: stackslib/src/chainstate/burn/operations/delegate_stx.rs)

### Summary
`DelegateStxOp::parse_from_tx` trusts the `sender` parameter it is handed by the caller without any cryptographic link to the victim, and `DelegateStxOp::check()` performs no authenticity or balance validation. Combined with `Burnchain::classify_transaction`'s resolution of `sender = &pre_stx.output`, an attacker who fully controls both outputs of their own `PreStxOp` Bitcoin transaction can set output 0 to the victim's Stacks-address hash160 (no private key required to *create* an output, only to *spend* it) while retaining control of output 1 to author the follow-up `DelegateStxOp`.

### Finding Description
The broken equality: a `.pox-4` delegation record for principal `P` must equal one where `P` actually authorized the delegation (via a signed `delegate-stx` Stacks tx or an op whose sender is cryptographically the address owning the spent UTXO). Here, `op.sender` is set purely from `PreStxOp.output`, which is an attacker-chosen Bitcoin output address requiring no possession of a private key to construct — only the second (`vout=1`) output of the same `PreStxOp` tx must actually be spent by the attacker to submit the `DelegateStxOp`, and that output is fully attacker-controlled since the attacker built and funded the `PreStxOp` tx themselves.

Code path:
1. `PreStxOp::parse_from_tx` reads `output` from Bitcoin output 0's address and converts it to a `StacksAddress` with no requirement that the creator control the corresponding key [1](#0-0) .
2. `Burnchain::classify_transaction` looks up the parsed `PreStxOp` by txid and passes `sender = &pre_stx.output` directly into `DelegateStxOp::from_tx` [2](#0-1) .
3. `DelegateStxOp::get_sender_txid` only requires that the `DelegateStxOp` tx's first input spends `vout=1` of some prior `PreStxOp` txid — it never validates who the payee of `vout=0` (the "sender"/victim label) actually is [3](#0-2) .
4. `DelegateStxOp::parse_from_tx` sets `sender: sender.clone()` verbatim from the untrusted, attacker-supplied value [4](#0-3) .
5. `DelegateStxOp::check()` only enforces `delegated_ustx != 0` and `until_burn_height <= i64::MAX` — no sender authenticity or balance check [5](#0-4) .
6. Downstream, when `.pox-4`'s `delegate-stx` contract-call path is processed, `handle_contract_call` writes a stacking/delegation asset-map entry keyed on `sender` with the attacker-chosen `delegated_ustx`/`delegate_to`, with no signature check tying it to the victim [6](#0-5) .

Once this forged delegation record exists for the victim's principal, the attacker (as the chosen `delegate_to`) can subsequently call `.pox-4`'s `delegate-stack-stx` naming the victim as `stacker`. That call passes `pox-4.clar`'s delegation check against the forged record, and `pox_lock_v4` will lock the victim's real unlocked STX balance as long as it is sufficient [7](#0-6) , directing PoX reward payouts to a reward address of the attacker's choosing.

None of the existing guards (`check()`'s positivity/height checks, or `SortitionHandleTx::check_transaction`) validate that `sender` corresponds to the party who actually created/authorized the `PreStxOp`/`DelegateStxOp` chain, because the protocol's authenticity model for these ops is "whoever can spend `PreStxOp` output 1", not "whoever owns the address encoded in output 0."

### Impact Explanation
An attacker can, at zero cost to the victim's consent, create a `.pox-4` delegation entry for the victim's Stacks principal with an attacker-chosen `delegate_to` and `delegated_ustx` (bounded only by the victim's real unlocked balance at lock time). Using that forged delegation, the attacker can later call `delegate-stack-stx` to lock the victim's genuine unlocked STX and direct future PoX/Bitcoin reward payouts to an address the attacker controls — theft of stacking rewards and temporary freezing of the victim's STX for the stacking period, matching the Critical/High impact categories (theft of locked-STX-derived rewards, unsigned stacking action). This is repeatable against any victim account with a nonzero unlocked balance and requires only the attacker's own BTC UTXOs.

### Likelihood Explanation
Preconditions: victim has some unlocked STX; attacker needs only their own BTC funds to build the `PreStxOp` + follow-up `DelegateStxOp` transactions (no bond-admin/pause-admin/miner/signer privilege required, consistent with the allowed unprivileged attacker model). This works in any reward-cycle phase, since `delegate-stx`/`delegate-stack-stx` do not require prepare-phase exclusion. Cost is one Bitcoin fee to submit two chained burnchain transactions; the attack is fully repeatable against multiple victims.

### Recommendation
Require that a `DelegateStxOp` (and its sibling `PreStxOp`-anchored ops) can only assert `sender = X` when the entity constructing the op actually controls the private key associated with `X`, or alternatively remove the ability for burnchain-anchored `delegate-stx` to set delegation for a principal without a companion Stacks-transaction signature from that principal. At minimum, cap `delegated_ustx` at the sender's actual balance at op-processing time and require a proof-of-ownership challenge (e.g., the "sender" output must itself be the one spent, not merely referenced) before recording a delegation.

### Proof of Concept
Rust test in `stackslib/src/chainstate/burn/operations/delegate_stx.rs` / `stackslib/src/burnchains/tests/db.rs` style, extending the existing `PreStxOp`/`DelegateStxOp` unit tests:
1. Construct a `PreStxOp` Bitcoin tx where output 0's address hash160 equals a victim `StacksAddress` the attacker does not control, and output 1 is a P2PKH address whose key the attacker holds.
2. Process the `PreStxOp` via `BurnchainDB`/`classify_transaction`, confirming `op.output == victim_address`.
3. Build a `DelegateStxOp` tx spending output 1 of the `PreStxOp` tx (signed by the attacker's key), with `delegate_to = attacker_address` and `delegated_ustx = u128::MAX` (or victim's real balance).
4. Run `Burnchain::classify_transaction` and confirm the resulting `DelegateStxOp.sender == victim_address` and `DelegateStxOp::check()` returns `Ok(())`.
5. Feed the op through block processing into `.pox-4`, and assert (equality check): before, `get-delegation-info` for the victim principal is `none`; after, it equals `(some {delegated-to: attacker, amount-ustx: attacker_chosen, ...})` despite no Stacks transaction ever being signed by the victim — demonstrating the AUTHORITY equality is broken.

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L106-126)
```rust
        let outputs = tx.get_recipients();
        assert!(!outputs.is_empty());

        let output = outputs
            .get(0)
            .ok_or_else(|| {
                warn!("Invalid tx: first output not found");
                op_error::InvalidInput
            })?
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: first output cannot be decoded");
                op_error::InvalidInput
            })?
            .address
            .clone()
            .try_into_stacks_address()
            .ok_or_else(|| {
                warn!("Invalid tx: first output must be representable as a StacksAddress");
                op_error::InvalidInput
            })?;
```

**File:** stackslib/src/burnchains/burnchain.rs (L964-983)
```rust
            x if x == Opcodes::DelegateStx as u8 => {
                let pre_stx_txid = DelegateStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stx)) = pre_stx_tx {
                    let sender = &pre_stx.output;
                    match DelegateStxOp::from_tx(block_header, burn_tx, sender) {
                        Ok(op) => Some(BlockstackOperationType::DelegateStx(op)),
                        Err(e) => {
                            warn!(
                                "Failed to parse delegate stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
                        }
                    }
```

**File:** stackslib/src/chainstate/burn/operations/delegate_stx.rs (L105-120)
```rust
    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: DelegateStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: DelegateStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }
```

**File:** stackslib/src/chainstate/burn/operations/delegate_stx.rs (L194-204)
```rust
        Ok(DelegateStxOp {
            sender: sender.clone(),
            reward_addr,
            delegate_to,
            delegated_ustx: data.delegated_ustx,
            until_burn_height: data.until_burn_height,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
```

**File:** stackslib/src/chainstate/burn/operations/delegate_stx.rs (L207-225)
```rust
    pub fn check(&self) -> Result<(), op_error> {
        if self.delegated_ustx == 0 {
            warn!("Invalid DelegateStxOp, must have positive ustx");
            return Err(op_error::DelegateStxMustBePositive);
        }

        if let Some(height) = self.until_burn_height {
            if height > i64::MAX as u64 {
                warn!(
                    "Invalid DelegateStxOp: until_burn_height exceeds i64::MAX";
                    "until_burn_height" => height,
                    "txid" => %self.txid,
                );
                return Err(op_error::InvalidInput);
            }
        }

        Ok(())
    }
```

**File:** pox-locking/src/pox_4.rs (L61-90)
```rust
/// Lock up STX for PoX for a time.  Does NOT touch the account nonce.
pub fn pox_lock_v4(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    lock_amount: u128,
    unlock_burn_height: u64,
) -> Result<(), LockingError> {
    assert!(unlock_burn_height > 0);
    assert!(lock_amount > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxAlreadyLocked);
    }
    if !snapshot.can_transfer(lock_amount)? {
        return Err(LockingError::PoxInsufficientBalance);
    }
    snapshot.lock_tokens_v4(lock_amount, unlock_burn_height)?;

    debug!(
        "PoX v4 lock applied";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
```

**File:** pox-locking/src/pox_4.rs (L425-454)
```rust
    if function_name == "delegate-stx" {
        // Update the asset map to reflect the delegation
        match (sender_opt, args.first()) {
            (Some(sender), Some(Value::UInt(amount))) => {
                // Reject any transaction that would overwrite an
                // existing asset-map stacking entry for `sender`.
                if global_context
                    .get_readonly_asset_map()?
                    .get_stacking(sender)
                    .is_some()
                {
                    return Err(VmExecutionError::from(
                        RuntimeCheckErrorKind::PoxStxAssetMapOverwrite,
                    ));
                }
                global_context.log_stacking(sender, *amount)?;
            }
            _ => {
                let msg = "Unreachable: failed to log STX delegation in PoX-4 delegate-stx call";
                // This should be unreachable!
                error!(
                    "{msg}";
                    "sender" => ?sender_opt,
                    "arg0" => ?args.first(),
                );
                return Err(VmExecutionError::Internal(VmInternalError::Expect(
                    msg.into(),
                )));
            }
        }
```
