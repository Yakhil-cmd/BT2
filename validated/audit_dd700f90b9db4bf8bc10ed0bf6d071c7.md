Based on my investigation, no additional check exists tying `sender` (the `PreStxOp.output` address) to a signature over the corresponding input. The flow is confirmed end-to-end.

### Title
Unsigned STX lock via forged `PreStxOp` output address impersonating victim as StackStx `sender` - ([File: stackslib/src/chainstate/burn/operations/stack_stx.rs])

### Summary
`PreStxOp::parse_from_tx` derives the future `StackStxOp.sender` purely from output[0] of a Bitcoin OP_RETURN transaction, an address field that requires no signature to populate, so any address (including a victim's) can be written there. `burnchain.rs` then binds this attacker-chosen address as the `sender` for the paired `StackStxOp`, and `process_stacking_ops` runs `pox-4`'s `stack-stx` with `tx-sender = sender`, locking the named account's real STX balance without any signature from that account.

### Finding Description
The claimed equality is: AUTHORITY - every stacking lock on principal P's `STXBalance` == a stacking action that P cryptographically authorized. In this code path that equality is broken because the "authorizing" address is copied from an unauthenticated Bitcoin transaction output, not from any signature.

- `PreStxOp::parse_from_tx` (stack_stx.rs lines 106-126) reads `outputs.get(0)....address` and converts it to a `StacksAddress` with no relation to who signed the tx's inputs. An attacker fully controls this field when crafting their own Bitcoin transaction.
- `burnchain.rs` (lines 929-943) resolves the `StackStxOp`'s `sender` by looking up the `PreStxOp` for the txid referenced by `StackStxOp::get_sender_txid`, which only checks `vout == 1` of the spent PreStx output (stack_stx.rs lines 232-247) — it never validates that the StackStx-tx signer is the same entity as `output[0]`. `let sender = &pre_stack_stx.output;` is passed straight into `StackStxOp::from_tx`.
- `StackStxOp::check()` (stack_stx.rs lines 399-419) only validates `stacked_ustx > 0`, `num_cycles` range, and signer-key format — it never checks that `sender` was authorized by anyone.
- `process_stacking_ops` (stackslib/src/chainstate/stacks/db/blocks.rs lines 4120-4130) executes `tx.run_contract_call(&sender.clone().into(), ..., "stack-stx", ...)`, meaning `tx-sender` inside pox-4's Clarity execution is literally the forged victim address `V`.
- pox-4.clar's `stack-stx` (lines 571-621) checks `(>= (stx-get-balance tx-sender) amount-ustx)` and `(is-none (get-stacker-info tx-sender))` — both check the victim `V`'s real state, and if satisfied, lock `V`'s STX via `pox_lock_v4` (pox-locking/src/pox_4.rs lines 62-90), which operates on `principal = stacker = V`.

Exploit flow: attacker broadcasts a PreStx tx with output[0] = victim `V`'s Bitcoin-derived address and output[1] = an attacker-spendable dust UTXO. Attacker then broadcasts a StackStx tx spending vout=1 of that PreStx txid, with attacker-chosen `stacked_ustx`, `num_cycles`, `signer_key`. No signature from `V` is required anywhere in this chain, only proof that the attacker can spend a Bitcoin UTXO they themselves control (output[1], which is their own change/dust output).

Existing guards fail to prevent this because:
- `verify-signer-key-sig`/`consume-signer-key-authorization` in pox-4.clar only proves ownership of the `signer-key`/reward address, not ownership of the STX being locked (`tx-sender`).
- `check-caller-allowed` only guards against a different contract-caller acting on `tx-sender`'s behalf; it is trivially satisfied here since the "call" is a direct contract-call with `tx-sender` set to the forged address by the node itself, not a nested contract-caller.
- No code path checks that the address in `PreStxOp.output` matches a public key that signed either the PreStx or StackStx Bitcoin transaction.

### Impact Explanation
The attacker can force-lock an arbitrary victim account's unlocked STX into pox-4 stacking for up to `POX_MAX_NUM_CYCLES` cycles, with an attacker-chosen `pox-addr`/`signer_key` receiving any stacking rewards/signer-weight tied to that stacked amount, while the victim never signed a transaction. This is a temporary freeze of the victim's staked STX and an unsigned stacking action — matching the "High" impact category (temporary freezing of staked funds / unsigned stacking action). It is repeatable each cycle the attacker chooses to target the victim again once any prior lock expires, and requires only a small amount of attacker BTC (a dust output) per exploitation, with no cost to the attacker beyond bitcoin transaction fees.

### Likelihood Explanation
Preconditions: victim `V` must have `>= stacked_ustx` unlocked STX and not be already stacking/delegating (checked by pox-4.clar, not by the attacker — the attacker just needs to pick a victim satisfying this, which is public on-chain information). No special phase restriction (prepare-phase, cycle-start) blocks this — any burn block that gets processed into a Stacks block can carry the ops. Attacker cost is a Bitcoin transaction fee for two small transactions; no signature or private key of the victim is needed at any point, making this fully feasible for any unprivileged actor with minimal BTC to spend on fees, and trivially repeatable against any account that meets the balance/non-stacking precondition.

### Recommendation
Bind `StackStxOp.sender` (and `PreStxOp.output`) to a cryptographically verified identity rather than an arbitrary, unauthenticated Bitcoin output address — e.g., require the StackStx-op's `sender` to be derived from the public key(s) that signed the corresponding Bitcoin input (the same key material used to construct the Stacks address), or require an explicit off-chain/on-chain signature from `sender` authorizing the specific `(stacked_ustx, num_cycles, signer_key)` parameters before `process_stacking_ops` performs the Clarity `stack-stx` call.

### Proof of Concept
Rust integration test on a booted testnet chainstate:
1. Create accounts `Victim` (funded with unlocked STX, not stacking) and `Attacker` (funded with BTC UTXOs).
2. Attacker crafts and broadcasts a `PreStxOp`-shaped Bitcoin transaction whose OP_RETURN output[0] address is `Victim`'s Bitcoin-derived address and output[1] is an attacker-controlled dust output.
3. Attacker broadcasts a `StackStxOp`-shaped Bitcoin transaction that spends vout=1 of the prior txid as input[0], with attacker-chosen `stacked_ustx`, `num_cycles`, `signer_key`.
4. Mine/process both burn blocks so `process_stacking_ops` executes.
5. Assert on both sides of the equality: before, `stx-account Victim` shows `locked == 0`; after, `stx-account Victim` shows `locked == stacked_ustx` and `unlock-height` set per attacker's `num_cycles`, despite `Victim` never submitting or signing any transaction — confirming AUTHORITY is broken.