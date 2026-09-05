### Title
Unauthenticated `sender` field in `StackStxOp`/`PreStxOp` allows locking arbitrary victims' STX without their consent - ([File: stackslib/src/chainstate/burn/operations/stack_stx.rs])

### Summary
`StackStxOp::get_sender_txid` (stack_stx.rs:232-247) only verifies that the spent input's `vout == 1`; the resolved `sender` for the resulting `stack-stx` lock is taken directly from the referenced `PreStxOp.output` field with no cryptographic proof that the account named there ever authorized this specific stacking action. Because `PreStxOp.output` is an arbitrary Bitcoin-address-encoded value chosen unilaterally by whoever mines the `PreStx` transaction (no signature from the named Stacks address is required to *pay to* that address), any unprivileged BTC holder can name a victim's Stacks address as `output`, later spend `vout=1` of that same transaction (which they themselves fully control, since they created it), and have PoX lock the victim's STX.

### Finding Description
The broken equality: `STX locked by stack-stx == STX whose owner explicitly authorized/committed this specific stacking action`. In practice `StackStxOp.sender` is set from `PreStxOp.output` [1](#0-0)  and `PreStxOp.output` is decoded purely from the first Bitcoin transaction output address with `try_into_stacks_address()` — no signature over that address, and no linkage to a private key the victim controls, is ever checked [2](#0-1) .

`StackStxOp::get_sender_txid` only enforces `vout == 1` on the spent PreStx transaction's second output, with no check that the referenced `PreStxOp` was ever consented to by the address it names, and no bound on how old/new it is [3](#0-2) . The classifier `Burnchain::classify_transaction` resolves `sender = pre_stack_stx.output` via `burnchain_db.find_burnchain_op`, with no freshness/height constraint tying it to the current `StackStx` transaction's block [4](#0-3) .

This resolved, unauthenticated `sender` is then used directly as `tx-sender` for a synthetic `stack-stx` contract call into pox-4, bypassing any Stacks-transaction-level signature check entirely: `run_contract_call(&sender.clone().into(), ...)` [5](#0-4) . Inside `pox-4.clar`'s `stack-stx`, the only checks are that `tx-sender` isn't already stacking/delegating and has sufficient unlocked balance, plus a signer-key-authorization check that authenticates the *signer* (pool key), not the staker [6](#0-5) . None of these guards verify that the entity named as `tx-sender` (the victim) ever authorized this action.

Exploit flow: attacker crafts a Bitcoin `PreStx` transaction whose first output pays (dust) to `hash160(victim)` (public information derivable from the victim's known Stacks c32 address) and whose second output (`vout=1`) is fully attacker-controlled change. The attacker later spends `vout=1` in a `StackStx` transaction with attacker-chosen `stacked_ustx`, `num_cycles`, `reward_addr`, `signer_key`. The node resolves `sender = victim`, and if `victim`'s unlocked STX balance ≥ `stacked_ustx`, pox-4 locks the victim's STX to the attacker-chosen reward address/signer for the attacker-chosen cycle count — the victim never signed anything on the Stacks side. Note the exploit does **not** actually require an "old, stale" PreStxOp as the question frames it — a freshly minted `PreStxOp` naming the victim works identically, since there is no authentication of `output` at all, staleness or otherwise.

### Impact Explanation
The victim's STX becomes locked (unable to transfer/spend) for the attacker-chosen `num_cycles`, to an attacker-chosen `reward_addr`/`signer_key`, without the victim's consent or signature. This is a temporary (not permanent — it unlocks at `unlock_height`) freezing of the victim's staked funds, and constitutes an unsigned stacking action performed on the victim's behalf — matching the rubric's High-severity categories ("temporary freezing of staked funds", "an unsigned stacking action"), rather than the "permanent freezing" claimed by the question (Critical). It is repeatable against any address whose current unlocked STX balance the attacker knows/estimates, at the cost of a small Bitcoin transaction fee per attempt, and does not require the attacker to be privileged in any way.

### Likelihood Explanation
Preconditions are minimal: the attacker needs no relationship to the victim, no access to the victim's keys, and no privileged role — only knowledge of the victim's public Stacks address (routinely public) and the ability to broadcast two ordinary Bitcoin transactions (as any regular Stacking flow does). The victim must simply have sufficient unlocked STX at the time the op is mined and not already be stacking/delegating. This is trivially and repeatably feasible for any attacker with minimal BTC for fees.

### Recommendation
Require an explicit, cycle-scoped, replay-protected cryptographic authorization from the `sender`/staker address itself (e.g., an EIP-712-style signed message analogous to the existing `signer-sig` mechanism, but authenticating the staker rather than only the signer), before allowing a burnchain-originated `StackStxOp` (and `DelegateStxOp`/`TransferStxOp`, which share the same pattern) to act on a given `sender`'s balance. At minimum, do not resolve `sender` solely from an arbitrary, unauthenticated `PreStxOp.output` field with no proof of key ownership over that address.

### Proof of Concept
Rust integration test plan (e.g. extending `stacks-node/src/tests/neon_integrations.rs` patterns already used for `PreStxOp`/`StackStxOp`):
1. Create `victim_addr` (a normal funded Stacks account) that never signs anything for stacking, and `attacker_sk` (a separate Bitcoin-funded keychain, no relation to victim).
2. From the attacker's Bitcoin keys, submit a `PreStxOp { output: victim_addr, .. }` where `vout=1`'s change goes to an attacker-controlled Bitcoin address (standard `submit_manual`/`build_pre_stacks_tx` flow, as in existing `pre_stx_op` tests) [7](#0-6) .
3. From the same attacker-controlled UTXO (`vout=1` of the PreStx tx), submit a `StackStxOp` naming an attacker-chosen `reward_addr`, `num_cycles`, and `stacked_ustx <= victim's balance`.
4. Assert, after the block is processed, that `op.sender == victim_addr` (per `StackStxOp::parse_from_tx`/`classify_transaction`), and that `get_balance(victim_addr)` reflects an STX lock (`STXBalance` locked amount increases and unlock height is set) — i.e. assert equality broken: `locked_amount(victim) > 0` even though `victim` never signed a `stack-stx` transaction and never authorized `attacker`'s chosen `reward_addr`/`signer_key`.
5. Repeat step 2-4 using a fresh (same-block) `PreStxOp` rather than a stale one to show staleness is not the determining factor — the identical unauthenticated-sender flaw applies regardless of block-height distance between `PreStx` and `StackStx`.

### Citations

**File:** stackslib/src/chainstate/burn/operations/mod.rs (L181-200)
```rust
#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub struct StackStxOp {
    pub sender: StacksAddress,
    /// the PoX reward address.
    /// NOTE: the address in .pox will be tagged as either p2pkh or p2sh; it's impossible to tell
    /// if it's a segwit-p2sh since that looks identical to a p2sh address.
    pub reward_addr: PoxAddress,
    /// how many ustx this transaction locks
    pub stacked_ustx: u128,
    pub num_cycles: u8,
    pub signer_key: Option<StacksPublicKeyBuffer>,
    pub max_amount: Option<u128>,
    pub auth_id: Option<u32>,

    // common to all transactions
    pub txid: Txid,                            // transaction ID
    pub vtxindex: u32,                         // index in the block where this tx occurs
    pub block_height: u64,                     // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash, // hash of the burn chain block header
}
```

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

**File:** stackslib/src/burnchains/burnchain.rs (L929-954)
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
                        Err(e) => {
                            warn!(
                                "Failed to parse stack stx tx";
                                "txid" => %burn_tx.txid(),
                                "data" => %to_hex(&burn_tx.data()),
                                "error" => ?e,
                            );
                            None
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

**File:** contrib/boot-contracts-unit-tests/boot_contracts/pox-4.clar (L586-604)
```text

      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; tx-sender principal must not be stacking
      (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))

      ;; Validate ownership of the given signer key
      (try! (consume-signer-key-authorization pox-addr (- first-reward-cycle u1) "stack-stx" lock-period signer-sig signer-key amount-ustx max-amount auth-id))
```

**File:** stacks-node/src/burnchains/bitcoin_regtest_controller.rs (L4503-4548)
```rust
        #[test]
        #[ignore]
        fn test_build_pre_stx_tx_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let keychain = utils::create_keychain();
            let miner_pubkey = keychain.get_pub_key();
            let mut op_signer = keychain.generate_op_signer();

            let mut config = utils::create_miner_config();
            config.burnchain.local_mining_public_key = Some(miner_pubkey.to_hex());

            let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let mut btc_controller = BitcoinRegtestController::new(config.clone(), None);
            btc_controller.bootstrap_chain(101); // now, one utxo exists

            let mut pre_stx_op = utils::create_templated_pre_stx_op();
            pre_stx_op.output = keychain.get_address(false);

            let tx = btc_controller
                .build_pre_stacks_tx(StacksEpochId::Epoch31, pre_stx_op.clone(), &mut op_signer)
                .expect("Build leader key should work");

            assert!(op_signer.is_disposed());

            assert_eq!(1, tx.version);
            assert_eq!(0, tx.lock_time);
            assert_eq!(1, tx.input.len());
            assert_eq!(3, tx.output.len());

            // utxos list contains the only existing utxo
            let used_utxos = btc_controller.get_all_utxos(&miner_pubkey);
            let input_0 = utils::txin_at_index(&tx, &op_signer, &used_utxos, 0);
            assert_eq!(input_0, tx.input[0]);

            let op_return = utils::txout_opreturn(&pre_stx_op, &config.burnchain.magic_bytes, 0);
            let op_change = utils::txout_opdup_change_legacy(&mut op_signer, 24_500);
            assert_eq!(op_return, tx.output[0]);
            assert_eq!(op_change, tx.output[1]);
        }
```
