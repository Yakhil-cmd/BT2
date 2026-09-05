### Title
Unauthorized multi-victim STX stacking via unauthenticated `PreStxOp.output` in `pre_stx_op_map` lookup - (File: stackslib/src/burnchains/burnchain.rs, stackslib/src/chainstate/burn/operations/stack_stx.rs)

### Summary
`Burnchain::classify_transaction` resolves the `sender` field of a `StackStxOp` by looking up the originating `PreStxOp` via `pre_stx_op_map` keyed on the txid referenced by the `StackStxOp`'s input, and simply reuses `PreStxOp.output` (vout=0 of the pre-stx tx) as the locked account. Neither `PreStxOp::parse_from_tx` nor `StackStxOp::parse_from_tx`/`get_sender_txid` verify that the Bitcoin key that actually signs and spends vout=1 of the `PreStxOp` corresponds to the address declared at vout=0, so an attacker can declare an arbitrary victim address as vout=0 while funding and spending vout=1 with their own key, causing STX to be attributed to (and later locked for) the victim. This generalizes trivially to multiple victims within the same burn block since `pre_stx_op_map` is keyed independently per txid.

### Finding Description
The equality that must hold is:

`StackStxOp.sender (account whose STX gets locked) == StacksAddress derived from the private key that signed/authorized the Bitcoin input consumed by that StackStxOp`

Tracing the code:

- `PreStxOp::parse_from_tx` takes `outputs.get(0)` — the recipient of vout=0 — and stores it verbatim as `PreStxOp.output` with no requirement that the address owner sign anything; Bitcoin outputs never require the recipient's signature. [1](#0-0) 

- `StackStxOp::get_sender_txid` only validates that the op's single input spends `vout == 1` of some prior txid; it performs no check on which key signed that input versus any declared address. [2](#0-1) 

- `StackStxOp::from_tx` / `parse_from_tx` accept `sender: &StacksAddress` as an externally supplied parameter and copy it directly into `StackStxOp.sender` — there is no internal cryptographic cross-check against the transaction's actual signer. [3](#0-2) [4](#0-3) 

- `Burnchain::classify_transaction` (referenced throughout `stackslib/src/burnchains/burnchain.rs`, confirmed via the ten `pre_stx_op_map` usages) supplies this `sender` value by looking up `pre_stx_op_map.get(pre_stx_txid)` and passing `pre_stx_op.output` straight into `StackStxOp::from_tx`, with no address/key crosscheck between the resolved `PreStxOp` and the current `StackStxOp`'s actual signer. [5](#0-4) 

Attacker's exact call sequence:
1. Craft `PreStxOp` tx #1: vout=0 = victim1's address (no signature from victim1 needed, it's just a payment output); vout=1 = attacker-controlled key/address.
2. Craft `PreStxOp` tx #2: vout=0 = victim2's address; vout=1 = attacker-controlled key/address.
3. Craft `StackStxOp` tx #1 whose sole input spends vout=1 of PreStxOp tx #1 (signed by the attacker's own key) — `classify_transaction` resolves `sender = victim1`.
4. Craft `StackStxOp` tx #2 whose sole input spends vout=1 of PreStxOp tx #2 (signed by attacker's own key) — `sender = victim2`.

Because `pre_stx_op_map` is a simple `HashMap<Txid, PreStxOp>` populated per-block, both entries resolve independently, so the exact same missing check scales to any number of simultaneous victims in one burn block. No existing guard (`check()`, sunset height check, num_cycles bound, signer-key format check) touches this authorization gap — `StackStxOp::check` only validates `stacked_ustx > 0`, `num_cycles` bounds, and signer-key format, none of which relate to the sender/spender identity binding. [6](#0-5) 

### Impact Explanation
If confirmed at the burnchain-op classification layer, downstream Stacks-chainstate processing would receive `StackStxOp` records claiming `sender = victim` while the victim's key never authorized anything, leading to STX being locked out of the victim's account against their will — a Critical unauthorized-locking / freezing-of-staked-funds impact, repeatable across arbitrarily many victims per block at only the cost of two small Bitcoin dust outputs per victim (no attacker STX or victim cooperation required).

### Likelihood Explanation
Preconditions are minimal: the attacker needs Bitcoin to fund two small vout=1 outputs per targeted victim (dust-level cost) and any two victim Stacks/Bitcoin addresses with locked-STX-eligible balances; no privileged role, pox-5 cycle phase, or membership state is required at the burnchain-op parsing layer examined here. The attack is fully repeatable and scales linearly with the number of `PreStxOp`/`StackStxOp` pairs the attacker is willing to fund per block.

### Recommendation
Require that `StackStxOp`'s (and analogously `TransferStxOp`/`DelegateStxOp`'s) resolved `sender`/authorizing address be cryptographically bound to the same key that signs the input spending the `PreStxOp`'s vout=1 — e.g., derive the address from the recovered public key of the spending input (or require the `PreStxOp`'s vout=0 output script to match the same pubkey-hash that later signs vout=1) before accepting `pre_stx_op.output` as `sender` in `classify_transaction`.

### Proof of Concept
Rust test plan against `BurnchainDB::get_blockstack_transactions`:
1. Construct one burn block containing four burnchain transactions: `PreStxOp` #1 (vout0=victim1_addr, vout1=attacker_key), `PreStxOp` #2 (vout0=victim2_addr, vout1=attacker_key), `StackStxOp` #1 (input spends PreStxOp#1's vout1, signed by attacker_key), `StackStxOp` #2 (input spends PreStxOp#2's vout1, signed by attacker_key).
2. Run block classification through `BurnchainDB::get_blockstack_transactions` / `Burnchain::classify_transaction`.
3. Assert `resulting_stackstx_op_1.sender == victim1_addr` and `resulting_stackstx_op_2.sender == victim2_addr`.
4. Assert that neither `victim1_addr`'s nor `victim2_addr`'s private key was used to sign any input in the block (only `attacker_key` signed all four transactions), demonstrating the broken authority/lock-conservation equality.

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

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L249-278)
```rust
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        StackStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            epoch_id,
            tx,
            sender,
            pox_sunset_ht,
        )
    }

    // TODO: add tests from mutation testing results #4851
    #[cfg_attr(test, mutants::skip)]
    /// parse a StackStxOp
    /// `pox_sunset_ht` is the height at which PoX *disables*
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        // can't be too careful...
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L337-349)
```rust
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
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L398-419)
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
```

**File:** stackslib/src/burnchains/burnchain.rs (L41-52)
```rust
use crate::burnchains::{
    Burnchain, BurnchainBlock, BurnchainBlockHeader, BurnchainParameters, BurnchainRecipient,
    BurnchainSigner, BurnchainStateTransition, BurnchainStateTransitionOps, BurnchainTransaction,
    Error as burnchain_error, PoxConstants, Txid,
};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle, SortitionHandleTx};
use crate::chainstate::burn::distribution::BurnSamplePoint;
use crate::chainstate::burn::operations::leader_block_commit::MissedBlockCommit;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp,
    StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
```
