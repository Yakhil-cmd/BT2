### Title
Unauthenticated `sender` binding in `PreStxOp`/`StackStxOp` allows an attacker to lock a victim's STX for the attacker's own PoX reward cycle - (File: stackslib/src/chainstate/burn/operations/stack_stx.rs)

### Summary
`PreStxOp::parse_from_tx` derives `output` purely from the first Bitcoin output address of an attacker-funded transaction, with no cryptographic link to any Stacks private key [1](#0-0) . `StackStxOp::get_sender_txid` only requires that the spending input be vout=1 of that PreStxOp [2](#0-1) , and the resolved `sender` is taken verbatim from `pre_stx.output` when constructing the `StackStxOp` [3](#0-2) [4](#0-3) . This lets an attacker who only controls their own Bitcoin UTXOs name an arbitrary victim `StacksAddress` as `sender`.

### Finding Description
The claimed equality — "STX locked by the applied `StackStxOp` == STX owned and controlled (via a real signature) by `sender`" — is broken because `sender` is populated from a free-form Bitcoin-output address field, not from any Stacks-signed authorization.

Exploit flow:
1. Attacker crafts a `PreStxOp` Bitcoin transaction from their own UTXO(s). The tx's first output (`vout=0`) can encode *any* address, including the victim's real `StacksAddress`, since `PreStxOp::parse_from_tx` simply takes `outputs[0].address` and converts it, with no requirement that the attacker prove ownership of that address's private key [1](#0-0) .
2. Attacker then spends `vout=1` of that same PreStx transaction in a `StackStxOp` Bitcoin transaction, satisfying the only structural check in `get_sender_txid` [2](#0-1) .
3. `StackStxOp::parse_from_tx` binds `sender = pre_stx.output` (the victim's address) and sets `reward_addr` to an address the attacker controls, taken from the StackStxOp tx's own first output [5](#0-4) .
4. When the burn op is applied to chainstate, the Stacks node executes the `stack-stx` contract call with `tx-sender` set to this attacker-chosen `sender` value (the victim's address), locking the victim's real, unlocked STX balance for the attacker-specified `num_cycles` and crediting PoX reward-cycle participation to the attacker's `reward_addr`.

No existing guard prevents this: `PreStxOp::parse_from_tx` and `StackStxOp::parse_from_tx` only validate tx structure (non-empty inputs/outputs, opcode, sunset height, data length) [6](#0-5) [7](#0-6) , and `StackStxOp::check` only validates `stacked_ustx > 0`, `num_cycles` range, and `signer_key` format — never that `sender` is cryptographically tied to the Bitcoin keys that funded the transaction [8](#0-7) . There is no requirement anywhere in this path that the address named in `PreStxOp.output` matches an address derivable from the Bitcoin public keys that signed either the PreStxOp or StackStxOp transaction inputs.

### Impact Explanation
The victim's real, unlocked STX is force-locked for a PoX reward cycle chosen by the attacker, with PoX rewards flowing to the attacker's `reward_addr` — this is an unsigned, unauthorized stacking action against the victim's funds and a temporary freezing of the victim's staked STX, while the attacker collects Bitcoin PoX rewards funded by STX they never owned or locked. This is repeatable against any address with a known, sufficient unlocked STX balance, for the cost of two low-value Bitcoin transactions per victim per attempt.

### Likelihood Explanation
Preconditions are minimal: the attacker needs only their own small amount of BTC to fund the two-transaction PreStxOp/StackStxOp UTXO chain, knowledge of the victim's `StacksAddress`, and confirmation that the victim currently holds at least `stacked_ustx` unlocked STX. No privileged role, signer key, or victim cooperation is required. The attack is fully attacker-controlled and repeatable across cycles and victims, subject only to burnchain op parsing being reached during a non-prepare-phase window like any legitimate PoX stacking transaction.

### Recommendation
Require that `PreStxOp.output` (and thus the derived `StackStxOp.sender`) be cryptographically tied to the Bitcoin transaction's signing key(s) — e.g., derive `sender` from the Bitcoin input's public key/address (as is done for miner-derived addresses elsewhere) rather than trusting an arbitrary output field, or require a Stacks-signed authorization/allowance from the named `sender` address before the burnchain op is permitted to move that account's STX.

### Proof of Concept
Rust integration test (extending `stackslib/src/burnchains/tests/db.rs` patterns already present, e.g. lines 489-525):
1. Boot chainstate with a funded victim `StacksAddress` V holding unlocked STX, and fund only attacker-controlled Bitcoin UTXOs.
2. Craft a `PreStxOp` Bitcoin tx from an attacker UTXO whose `vout=0` output address encodes V (not any address the attacker controls the private key for) — this passes `PreStxOp::parse_from_tx`.
3. Craft a `StackStxOp` Bitcoin tx spending `vout=1` of the PreStxOp tx, with reward address R controlled by the attacker — this passes `StackStxOp::get_sender_txid`/`parse_from_tx` and yields `op.sender == V`, `op.reward_addr == R`.
4. Process the burn block and the following Stacks block; assert `op.sender == V` (as in the existing test at stackslib/src/burnchains/tests/db.rs:517-521) and then query the chainstate for V's locked STX balance, asserting it increased by `stacked_ustx` despite V never signing any Stacks or Bitcoin transaction, and that the PoX reward slot for the cycle credits R. [9](#0-8)

### Citations

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L80-144)
```rust
    ) -> Result<PreStxOp, op_error> {
        // can't be too careful...
        let num_inputs = tx.num_signers();
        let num_outputs = tx.num_recipients();

        if num_inputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                num_inputs, num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if num_outputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                num_inputs, num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::PreStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

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

        // check if we've reached PoX disable
        if PoxConstants::has_pox_sunset(epoch_id) && block_height >= pox_sunset_ht {
            debug!(
                "PreStxOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(PreStxOp {
            output,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L270-350)
```rust
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        // can't be too careful...
        let num_outputs = tx.num_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs
            );
            return Err(op_error::InvalidInput);
        }

        if num_outputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::StackStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = StackStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let outputs = tx.get_recipients();
        assert!(!outputs.is_empty());

        let first_output = outputs
            .get(0)
            .ok_or_else(|| {
                warn!("Invalid tx: no first output");
                op_error::InvalidInput
            })?
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: failed to decode first output");
                op_error::InvalidInput
            })?;

        // coerce a hash mode for this address if need be, since we'll need it when we feed this
        // address into the .pox contract
        let reward_addr = first_output.address.clone().coerce_hash_mode();

        // check if we've reached PoX disable
        if PoxConstants::has_pox_sunset(epoch_id) && block_height >= pox_sunset_ht {
            debug!(
                "StackStxOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(StackStxOp {
            sender: sender.clone(),
            reward_addr,
            stacked_ustx: data.stacked_ustx,
            num_cycles: data.num_cycles,
            signer_key: data.signer_key,
            max_amount: data.max_amount,
            auth_id: data.auth_id,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L398-420)
```rust
impl StackStxOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.stacked_ustx == 0 {
            warn!("Invalid StackStxOp, must have positive ustx");
            return Err(op_error::StackStxMustBePositive);
        }

        if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
            warn!(
                "Invalid StackStxOp, num_cycles = {}, but must be in (0, {}]",
                self.num_cycles, POX_MAX_NUM_CYCLES
            );
        }

        // Check to see if the signer key is valid if available
        if let Some(signer_key) = &self.signer_key {
            Secp256k1PublicKey::from_slice(signer_key.as_bytes())
                .map_err(|_| op_error::StackStxInvalidKey)?;
        }

        Ok(())
    }
}
```

**File:** stackslib/src/burnchains/burnchain.rs (L929-935)
```rust
            x if x == Opcodes::StackStx as u8 => {
                let pre_stx_txid = StackStxOp::get_sender_txid(burn_tx).ok()?;
                let pre_stx_tx = match pre_stx_op_map.get(pre_stx_txid) {
                    Some(tx_ref) => Some(BlockstackOperationType::PreStx(tx_ref.clone())),
                    None => burnchain_db.find_burnchain_op(indexer, pre_stx_txid),
                };
                if let Some(BlockstackOperationType::PreStx(pre_stack_stx)) = pre_stx_tx {
```

**File:** stackslib/src/burnchains/tests/db.rs (L511-521)
```rust
    if let BlockstackOperationType::PreStx(op) = &processed_ops_0[0] {
        assert_eq!(&op.output, &expected_pre_stack_addr);
    } else {
        panic!("EXPECTED to parse a pre stack stx op");
    }

    if let BlockstackOperationType::StackStx(op) = &processed_ops_1[0] {
        assert_eq!(&op.sender, &expected_pre_stack_addr);
        assert_eq!(&op.reward_addr, &expected_reward_addr);
        assert_eq!(op.stacked_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.num_cycles, 1);
```
