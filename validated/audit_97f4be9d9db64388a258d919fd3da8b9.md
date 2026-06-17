### Title
Oracle-Provided `native_price` and `pubdata_price` Are Not Validated at Block Initialization, Enabling Operator-Controlled Fee Manipulation - (File: `basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs`)

---

### Summary

The `BlockMetadataFromOracle` struct, which carries ZKsync-specific pricing fields `native_price` and `pubdata_price`, is deserialized from the oracle at block initialization without any validation of those pricing fields. The only post-deserialization check is a gas-limit upper-bound. A zero or manipulated `native_price` is not caught until the first transaction is processed, and `pubdata_price` has no validation at all at the block level. Critically, the documentation explicitly acknowledges that `native_price` and `gas_per_pubdata` are **not** included in the block header commitment, meaning these values are not constrained by the ZK proof's public inputs.

---

### Finding Description

**Root cause — `metadata_op.rs`:**

```rust
// basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs
let block_level_metadata: BlockMetadataFromOracle =
    oracle.query_with_empty_input(BLOCK_METADATA_QUERY_ID)?;

let metadata = ZkMetadata { ... };

if metadata.block_gas_limit() > MAX_BLOCK_GAS_LIMIT
    || metadata.individual_tx_gas_limit() > MAX_TX_GAS_LIMIT
{
    return Err(internal_error!("block or tx gas limit is too high"));
}
``` [1](#0-0) 

The only validation performed on the oracle-returned `BlockMetadataFromOracle` is a gas-limit upper-bound check. The fields `native_price`, `pubdata_price`, `eip1559_basefee`, `pubdata_limit`, and `blob_fee` are accepted without any range or sanity checks.

**`BlockMetadataFromOracle` deserialization — `zk_metadata.rs`:**

The `from_iter` implementation blindly deserializes all fields including `native_price` and `pubdata_price` with no validation:

```rust
fn from_iter(src: &mut impl ExactSizeIterator<Item = usize>) -> Result<Self, InternalError> {
    let eip1559_basefee = UsizeDeserializable::from_iter(src)?;
    let pubdata_price = UsizeDeserializable::from_iter(src)?;
    let native_price = UsizeDeserializable::from_iter(src)?;
    ...
    Ok(new)
}
``` [2](#0-1) 

**The zero-check for `native_price` is deferred to per-transaction validation:**

```rust
// validation_impl.rs
if native_price.is_zero() {
    return Err(internal_error!("Native price cannot be 0").into());
}
``` [3](#0-2) 

This check fires only during L2 transaction validation. For service transactions, `gas_price` is forced to `U256::ZERO` and the `native_price` zero-check path is still reached — but the check is inside `validate_and_compute_fee_for_transaction`, which is only called for L2 EOA transactions, not for all transaction types uniformly.

**The documentation confirms `native_price` is NOT in the block header / public inputs:**

> "Currently it misses `gas_per_pubdata` and `native_price`, but we already working on design and implementation to solve this issue." [4](#0-3) 

This means the ZK proof does **not** constrain `native_price` or `pubdata_price`. A prover/sequencer can supply any value for these fields via the oracle without the proof being invalidated.

**`pubdata_price` has no block-level validation at all.** The `ZkSpecificPricingMetadata` implementation simply returns the raw oracle value:

```rust
impl ZkSpecificPricingMetadata for BlockMetadataFromOracle {
    fn get_pubdata_price(&self) -> U256 { self.pubdata_price }
    fn native_price(&self) -> U256 { self.native_price }
``` [5](#0-4) 

---

### Impact Explanation

**Fee accounting manipulation (resource accounting bug / oracle IO mismatch):**

1. **`native_price = U256::MAX` (or any extreme value):** `native_per_gas = ceil(gas_price / native_price)` rounds to 0. When `native_per_gas == 0`, the system sets `native_limit = u64::MAX - 1`, effectively granting unlimited native resources to every transaction in the block. This bypasses the ZK proving cost accounting entirely — transactions that would normally be rejected for insufficient native resources are accepted.

2. **`pubdata_price = U256::MAX`:** `native_per_pubdata = pubdata_price.wrapping_div(native_price)` can overflow or produce an extreme value, causing every transaction to be charged an enormous amount of native resources for pubdata, effectively DoS-ing all user transactions in the block.

3. **`pubdata_price = 0`:** All pubdata is free. Users pay no cost for state writes, enabling state bloat attacks at zero marginal cost.

4. **`eip1559_basefee = 0`:** Accepted without validation. Combined with `native_price` manipulation, this allows transactions with zero gas price to pass all fee checks.

Since `native_price` and `pubdata_price` are not committed to in the ZK proof's public inputs, a malicious or compromised sequencer/prover can supply arbitrary values and generate a valid proof. The settlement layer cannot detect the manipulation.

---

### Likelihood Explanation

The sequencer controls the oracle data fed into the system. In the proving path, the prover also controls the oracle. Since these fields are explicitly documented as missing from the block header commitment, any sequencer operator can set `native_price` and `pubdata_price` to arbitrary values per block. This is a **privileged operator** action — however, the Immunefi scope for ZKsync OS includes "prover/forward execution input" as an attacker-controlled entry path, and the oracle is exactly that input channel. The likelihood is **medium-high** for a compromised or malicious sequencer scenario.

---

### Recommendation

1. **Validate `native_price` and `pubdata_price` at block initialization** in `metadata_op.rs`, immediately after oracle deserialization — before any transaction is processed. Reject blocks with `native_price == 0`, `pubdata_price > MAX_REASONABLE_PUBDATA_PRICE`, etc.

2. **Include `native_price` and `pubdata_price` in the block header / public inputs** so the ZK proof constrains these values. The documentation already acknowledges this gap.

3. **Add a `pubdata_limit` upper-bound check** analogous to the existing gas-limit check.

---

### Proof of Concept

**Step 1:** Sequencer constructs a `BlockMetadataFromOracle` with `native_price = U256::MAX` and `pubdata_price = U256::ZERO`.

**Step 2:** The oracle responds to `BLOCK_METADATA_QUERY_ID` with this crafted metadata.

**Step 3:** `metadata_op` deserializes it — only the gas-limit check fires, which passes normally. [6](#0-5) 

**Step 4:** For each L2 transaction, `validation_impl.rs` computes:
```
native_per_gas = ceil(gas_price / U256::MAX) = 0
```
Then hits the branch:
```rust
let native_limit = if native_per_gas == 0 { u64::MAX - 1 } else { ... };
``` [7](#0-6) 

Every transaction in the block receives `native_limit = u64::MAX - 1`, bypassing all native resource accounting. Simultaneously, `pubdata_price = 0` means `native_per_pubdata = 0`, so all pubdata is free.

**Step 5:** The resulting ZK proof is valid because `native_price` and `pubdata_price` are not part of the public input commitment, as confirmed by the documentation. [4](#0-3)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs (L17-34)
```rust
    ) -> Result<<S as SystemTypes>::Metadata, InternalError> {
        let block_level_metadata: BlockMetadataFromOracle =
            oracle.query_with_empty_input(BLOCK_METADATA_QUERY_ID)?;

        let metadata = ZkMetadata {
            tx_level: TxLevelMetadata::default(),
            block_level: block_level_metadata,
            _marker: core::marker::PhantomData,
        };

        if metadata.block_gas_limit() > MAX_BLOCK_GAS_LIMIT
            || metadata.individual_tx_gas_limit() > MAX_TX_GAS_LIMIT
        {
            return Err(internal_error!("block or tx gas limit is too high"));
        }

        Ok(metadata)
    }
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L193-203)
```rust
impl ZkSpecificPricingMetadata for BlockMetadataFromOracle {
    fn get_pubdata_price(&self) -> U256 {
        self.pubdata_price
    }
    fn native_price(&self) -> U256 {
        self.native_price
    }
    fn get_pubdata_limit(&self) -> u64 {
        self.pubdata_limit
    }
}
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L271-301)
```rust
    fn from_iter(src: &mut impl ExactSizeIterator<Item = usize>) -> Result<Self, InternalError> {
        let eip1559_basefee = UsizeDeserializable::from_iter(src)?;
        let pubdata_price = UsizeDeserializable::from_iter(src)?;
        let native_price = UsizeDeserializable::from_iter(src)?;
        let block_number = UsizeDeserializable::from_iter(src)?;
        let timestamp = UsizeDeserializable::from_iter(src)?;
        let chain_id = UsizeDeserializable::from_iter(src)?;
        let gas_limit = UsizeDeserializable::from_iter(src)?;
        let pubdata_limit = UsizeDeserializable::from_iter(src)?;
        let coinbase = UsizeDeserializable::from_iter(src)?;
        let block_hashes = UsizeDeserializable::from_iter(src)?;
        let mix_hash = UsizeDeserializable::from_iter(src)?;
        let blob_fee = UsizeDeserializable::from_iter(src)?;

        let new = Self {
            eip1559_basefee,
            pubdata_price,
            native_price,
            block_number,
            timestamp,
            chain_id,
            gas_limit,
            pubdata_limit,
            coinbase,
            block_hashes,
            mix_hash,
            blob_fee,
        };

        Ok(new)
    }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L121-124)
```rust
    let native_per_gas = {
        if native_price.is_zero() {
            return Err(internal_error!("Native price cannot be 0").into());
        }
```

**File:** docs/bootloader/bootloader.md (L35-36)
```markdown
The block header should determine the block fully, i.e. include all the inputs needed to execute the block.
Currently it misses `gas_per_pubdata` and `native_price`, but we already working on design and implementation to solve this issue.
```

**File:** api/src/helpers.rs (L430-434)
```rust
    let native_limit = if native_per_gas == 0 {
        u64::MAX - 1
    } else {
        native_per_gas.saturating_mul(gas_limit)
    };
```
