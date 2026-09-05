### Title
Unauthenticated `StackStxOp.sender` lets a Bitcoin-only attacker lock a victim's STX and steal PoX rewards via `stack-stx` - (File: stackslib/src/chainstate/burn/operations/stack_stx.rs)

### Summary
`PreStxOp::parse_from_tx` accepts *any* `StacksAddress` as `output` with zero proof that the Bitcoin transaction submitter controls the corresponding Stacks private key [1](#0-0) . `StackStxOp::get_sender_txid`/`parse_from_tx` then copy that unauthenticated address into `StackStxOp.sender` merely by spending vout=1 of the `PreStxOp` transaction [2](#0-1) , and `process_stacking_ops` invokes pox's `stack-stx` with that address as `tx-sender` [3](#0-2) , with no Stacks-transaction signature ever required.

### Finding Description
The broken equality: **"every stacking action == one the staker (`tx-sender`) or their signer signed"** vs. actual: `tx-sender` in the `stack-stx` contract call is set from `StackStxOp.sender`, which is copied verbatim from `PreStxOp.output` [4](#0-3) . `PreStxOp.output` is parsed purely from the first Bitcoin transaction output's address with no cryptographic link to any Stacks key [5](#0-4) .

Exploit flow:
1. Attacker (owns only BTC UTXOs, their own `signer-key`, and their own valid signer signature) submits a `PreStxOp` whose `output` names the victim's `StacksAddress`.
2. Attacker submits a follow-up `StackStxOp` spending vout=1 of that `PreStxOp` tx, with `reward_addr` pointing to the attacker's own Bitcoin/PoX address, `signer_key`/`signer_sig` from the attacker's own signer key, and `stacked_ustx` ≤ victim's unlocked balance.
3. `classify_transaction` resolves `sender = pre_stx.output = victim` and constructs the `StackStxOp` [4](#0-3) .
4. `process_stacking_ops` calls `pox-N`'s `stack-stx` with `tx-sender = victim`, `signer-key`/`signer-sig` from the attacker [3](#0-2) .
5. Inside `stack-stx`, the checks that run are: `is-none (get-stacker-info tx-sender)`, `is-none (get-check-delegation tx-sender)`, and `stx-get-balance tx-sender >= amount-ustx` — all about the victim's account state, not about who authorized the call [6](#0-5) .
6. Critically, `consume-signer-key-authorization`/`verify-signer-key-sig` validate the *signer key's* signature over a message hash that contains only `{pox-addr, reward-cycle, topic, period, auth-id, max-amount}` — **it never includes `tx-sender`/stacker identity** [7](#0-6) . So the attacker's own, self-generated, valid signer authorization is accepted regardless of which principal is stacking.
7. The contract locks `amount-ustx` from the victim's real STX balance (`map-set stacking-state {stacker: tx-sender} ...`) and credits the reward-cycle slot to the attacker's chosen `pox-addr`/`signer-key` [8](#0-7) , and the STX lock is subsequently applied via `pox_lock_v4`/`pox_lock_v5` against the victim's `STXBalance` [9](#0-8) .

Existing guards fail because they check *balance/state of the named address*, not *authorization of the caller*: there is no signature check tying the `PreStxOp.output`/`StackStxOp.sender` address to a Stacks-level signature, and the signer-key authorization message is deliberately address-agnostic.

### Impact Explanation
The victim's STX get locked (frozen) for `num_cycles` reward cycles without their consent — a direct breach of AUTHORITY. Simultaneously, the PoX/BTC rewards for that locked value accrue to the attacker's own `reward_addr`/`signer-key`, i.e. the attacker earns stacking rewards backed entirely by the victim's capital while risking none of their own STX. This is repeatable against any address with unlocked STX and no pre-existing PoX registration, for the cost of two low-value Bitcoin transactions. Matches Critical ("theft ... of ... sBTC rewards, permanent/temporary freezing of staked STX ... an unsigned stacking action") since the victim's STX is locked and rewards are diverted from a completely unsigned, unauthorized action.

### Likelihood Explanation
Preconditions: victim must have an unlocked STX balance and not already be stacking/delegating (a very common state for most STX holders). Attacker needs only: a Bitcoin UTXO to fund the two-transaction `PreStxOp`+`StackStxOp` op sequence, and their own signer key/signature (something any unprivileged actor can generate independently, since it is never bound to the stacker's identity). No signer-manager role, bond admin, pause admin, victim key, or miner privilege is required. This is trivially repeatable against many victim addresses in parallel and works on any cycle not in prepare-phase (`verify-not-prepare-phase` does not check caller/sender authorization, only cycle timing).

### Recommendation
Bind the burnchain stacking authorization to the actual Stacks-key owner: either (a) require `PreStxOp`/`StackStxOp` to be signed by, or otherwise cryptographically prove control of, the named `output`/`sender` StacksAddress before it can be used as `tx-sender` in `stack-stx`, or (b) include the target stacker principal (`tx-sender`) inside the SIP-018 message hash checked in `get-signer-key-message-hash`/`verify-signer-key-sig`, so a signer-key authorization cannot be replayed against an arbitrary unauthenticated stacker.

### Proof of Concept
Rust integration test (e.g., extending `nakamoto_integrations.rs` burnchain-op tests):
1. Set up victim address `V` with unlocked STX ≥ minimum stacking threshold, and never have `V` sign or broadcast anything.
2. Attacker `A` funds a BTC UTXO, generates their own `signer_key`/`signer_sig` for `topic = "stack-stx"`, `pox-addr = A`'s reward address, `auth-id`, `max-amount`.
3. Submit `PreStxOp { output: V, .. }` via `classify_transaction`/`submit_operation`.
4. Submit `StackStxOp { sender: V (auto-resolved), reward_addr: A_reward_addr, signer_key: A_signer_key, .. }` spending vout=1 of the `PreStxOp` tx.
5. Mine the block, run `process_stacking_ops`.
6. Assert: `stacking-state` map entry exists for `V` (equality broken: `V` never signed a Stacks transaction, yet `get-stacker-info V` is `Some`), `V`'s `STXBalance` shows locked amount, and the reward-cycle PoX address list contains `A`'s `pox-addr`/`signer-key` credited with `V`'s locked amount.

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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L232-247)
```rust
    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: StackStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: StackStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }
```

**File:** stackslib/src/chainstate/stacks/db/blocks.rs (L4120-4130)
```rust
            let result = clarity_tx.connection().as_transaction(|tx| {
                tx.run_contract_call(
                    &sender.clone().into(),
                    None,
                    &boot_code_id(active_pox_contract, mainnet),
                    "stack-stx",
                    &args,
                    |_, _| None,
                    &ResourceBudget::unlimited(),
                )
            });
```

**File:** stackslib/src/burnchains/burnchain.rs (L929-944)
```rust
            x if x == Opcodes::StackStx as u8 => {
                let pre_stx_txid = StackStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stack_stx)) = pre_stx_tx {
                    let sender = &pre_stack_stx.output;
                    match StackStxOp::from_tx(
                        block_header,
                        epoch_id,
                        burn_tx,
                        sender,
                        burnchain.pox_constants.sunset_end,
                    ) {
                        Ok(op) => Some(BlockstackOperationType::StackStx(op)),
```

**File:** contrib/boot-contracts-unit-tests/boot_contracts/pox-4.clar (L591-601)
```text
      ;; tx-sender principal must not be stacking
      (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))
```

**File:** contrib/boot-contracts-unit-tests/boot_contracts/pox-4.clar (L606-621)
```text
      ;; ensure that stacking can be performed
      (try! (can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))

      ;; register the PoX address with the amount stacked
      (let ((reward-set-indexes (try! (add-pox-addr-to-reward-cycles pox-addr first-reward-cycle lock-period amount-ustx tx-sender signer-key))))
          ;; add stacker record
         (map-set stacking-state
           { stacker: tx-sender }
           { pox-addr: pox-addr,
             reward-set-indexes: reward-set-indexes,
             first-reward-cycle: first-reward-cycle,
             lock-period: lock-period,
             delegated-to: none })

          ;; return the lock-up information, so the node can actually carry out the lock.
          (ok { stacker: tx-sender, lock-amount: amount-ustx, signer-key: signer-key, unlock-burn-height: (reward-cycle-to-burn-height (+ first-reward-cycle lock-period)) }))))
```

**File:** contrib/boot-contracts-unit-tests/boot_contracts/pox-4.clar (L687-763)
```text
;; Generate a message hash for validating a signer key.
;; The message hash follows SIP018 for signing structured data. The structured data
;; is the tuple `{ pox-addr: { version, hashbytes }, reward-cycle, auth-id, max-amount }`.
;; The domain is `{ name: "pox-4-signer", version: "1.0.0", chain-id: chain-id }`.
(define-read-only (get-signer-key-message-hash (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                               (reward-cycle uint)
                                               (topic (string-ascii 14))
                                               (period uint)
                                               (max-amount uint)
                                               (auth-id uint))
  (sha256 (concat
    SIP018_MSG_PREFIX
    (concat
      (sha256 (unwrap-panic (to-consensus-buff? { name: "pox-4-signer", version: "1.0.0", chain-id: chain-id })))
      (sha256 (unwrap-panic
        (to-consensus-buff? {
          pox-addr: pox-addr,
          reward-cycle: reward-cycle,
          topic: topic,
          period: period,
          auth-id: auth-id,
          max-amount: max-amount,
        })))))))

;; Verify a signature from the signing key for this specific stacker.
;; See `get-signer-key-message-hash` for details on the message hash.
;;
;; Note that `reward-cycle` corresponds to the _current_ reward cycle,
;; when used with `stack-stx` and `stack-extend`. Both the reward cycle and
;; the lock period are inflexible, which means that the stacker must confirm their transaction
;; during the exact reward cycle and with the exact period that the signature or authorization was
;; generated for.
;; 
;; The `amount` field is checked to ensure it is not larger than `max-amount`, which is
;; a field in the authorization. `auth-id` is a random uint to prevent authorization
;; replays.
;;
;; This function does not verify the payload of the authorization. The caller of
;; this function must ensure that the payload (reward cycle, period, topic, and pox-addr)
;; are valid according to the caller function's requirements.
;;
;; When `signer-sig` is present, the public key is recovered from the signature
;; and compared to `signer-key`. If `signer-sig` is `none`, the function verifies that an authorization was previously
;; added for this key.
;; 
;; This function checks to ensure that the authorization hasn't been used yet, but it
;; does _not_ store the authorization as used. The function `consume-signer-key-authorization`
;; handles that, and this read-only function is exposed for client-side verification.
(define-read-only (verify-signer-key-sig (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                         (reward-cycle uint)
                                         (topic (string-ascii 14))
                                         (period uint)
                                         (signer-sig-opt (optional (buff 65)))
                                         (signer-key (buff 33))
                                         (amount uint)
                                         (max-amount uint)
                                         (auth-id uint))
  (begin
    ;; Validate that amount is less than or equal to `max-amount`
    (asserts! (>= max-amount amount) (err ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH))
    (asserts! (is-none (map-get? used-signer-key-authorizations { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
              (err ERR_SIGNER_AUTH_USED))
    (match signer-sig-opt
      ;; `signer-sig` is present, verify the signature
      signer-sig (ok (asserts!
        (is-eq
          (unwrap! (secp256k1-recover?
            (get-signer-key-message-hash pox-addr reward-cycle topic period max-amount auth-id)
            signer-sig) (err ERR_INVALID_SIGNATURE_RECOVER))
          signer-key)
        (err ERR_INVALID_SIGNATURE_PUBKEY)))
      ;; `signer-sig` is not present, verify that an authorization was previously added for this key
      (ok (asserts! (default-to false (map-get? signer-key-authorizations
            { signer-key: signer-key, reward-cycle: reward-cycle, period: period, topic: topic, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
          (err ERR_NOT_ALLOWED)))
    ))
  )
```

**File:** pox-locking/src/pox_4.rs (L195-213)
```rust
    let (stacker, locked_amount, unlock_height) = match parse_pox_stacking_result(value) {
        Ok(x) => x,
        Err(_) => {
            // nothing to do -- the function failed
            return Ok(None);
        }
    };

    match pox_lock_v4(
        &mut global_context.database,
        &stacker,
        locked_amount,
        unlock_height,
    ) {
        Ok(_) => {
            // For direct stacking, we log the locked amount in the asset map.
            if function_name == "stack-stx" {
                global_context.log_stacking(&stacker, locked_amount)?;
            }
```
