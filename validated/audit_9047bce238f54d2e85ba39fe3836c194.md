### Title
Mempool Fee Escalation Check Ignores L1 Gas and L1 Data Gas Price Bounds, Allowing Fee-Reduction Replacements — (`crates/apollo_mempool/src/mempool.rs`)

---

### Summary

The mempool's `should_replace_tx` fee escalation check evaluates only `tip` and `max_l2_gas_price` when deciding whether an incoming transaction may replace an existing one at the same `(address, nonce)`. The `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` components of `AllResourceBounds` are never extracted into `TransactionReference` or `ValidationArgs` and are therefore invisible to every escalation comparison. A sender can craft a replacement that satisfies the two checked dimensions while slashing the unchecked L1 price bounds to the bare minimum required by blockifier validation, producing a replacement whose total committed fee is far below the original — the opposite of what fee escalation is meant to enforce.

---

### Finding Description

`TransactionReference` is the lightweight struct used for all queue and escalation logic inside the mempool:

```rust
pub struct TransactionReference {
    pub address: ContractAddress,
    pub nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,   // ← only L2 gas price is stored
}
``` [1](#0-0) 

Its constructor extracts only `l2_gas.max_price_per_unit`:

```rust
max_l2_gas_price: tx.resource_bounds().l2_gas.max_price_per_unit,
``` [2](#0-1) 

`ValidationArgs`, which the gateway sends to the mempool's `validate_tx` path, is constructed the same way — only `l2_gas.max_price_per_unit` is forwarded:

```rust
max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
``` [3](#0-2) 

`should_replace_tx` therefore compares only two of the three price dimensions:

```rust
fn should_replace_tx(&self, existing_tx: &TransactionReference, incoming_tx: &TransactionReference) -> bool {
    let [existing_tip, incoming_tip] = [existing_tx, incoming_tx].map(|tx| u128::from(tx.tip.0));
    let [existing_max_l2_gas_price, incoming_max_l2_gas_price] =
        [existing_tx, incoming_tx].map(|tx| tx.max_l2_gas_price.0);
    self.increased_enough(existing_tip, incoming_tip)
        && self.increased_enough(existing_max_l2_gas_price, incoming_max_l2_gas_price)
}
``` [4](#0-3) 

`l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` are never consulted. The same incomplete check is applied in both the gateway's pre-admission `validate_tx` call and the final `add_tx_validations` call: [5](#0-4) [6](#0-5) 

The stateful gateway validator's `validate_resource_bounds` also checks only the L2 gas price against the previous block's threshold, with an explicit TODO acknowledging the gap:

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(...)
``` [7](#0-6) 

The correct total committed fee — used by the blockifier and the OS — sums all three resource dimensions:

```rust
return l1_gas_bounds.max_amount * l1_gas_bounds.max_price_per_unit
     + l2_gas_bounds.max_amount * (l2_gas_bounds.max_price_per_unit + tx_info.tip)
     + l1_data_gas_bounds.max_amount * l1_data_gas_bounds.max_price_per_unit;
``` [8](#0-7) 

The mempool's escalation check uses only a strict subset of this sum, mirroring the stableswap bug where only the ask/offer token pair was used instead of all pool tokens.

---

### Impact Explanation

**Broken invariant:** Fee escalation is supposed to guarantee that every replacement transaction commits to a strictly higher total fee than the transaction it displaces, making mempool spam economically costly. Because only `tip` and `max_l2_gas_price` are checked, this invariant does not hold.

**Concrete attack:** Suppose an existing transaction carries:
- `tip = 100`, `max_l2_gas_price = 100`, `l1_gas.max_price = 50_000`, `l1_data_gas.max_price = 50_000`

A replacement with `fee_escalation_percentage = 10` passes `should_replace_tx` if:
- `tip ≥ 110`, `max_l2_gas_price ≥ 110`

The attacker sets `l1_gas.max_price` and `l1_data_gas.max_price` to the bare minimum that satisfies blockifier's `check_fee_bounds` (i.e., exactly the current block's L1 gas price). The replacement is admitted to the mempool with a total committed fee that is orders of magnitude lower than the original, despite the escalation check returning `true`.

**Downstream effects:**
1. The sequencer's expected fee revenue from the transaction is silently reduced after admission.
2. The replacement may revert during execution if actual L1 gas consumption exceeds the slashed bound, wasting sequencer resources.
3. The spam-prevention property of fee escalation is defeated: an attacker can cycle replacements cheaply by keeping `tip` and `max_l2_gas_price` just above the escalation threshold while zeroing out L1 price commitments.

This matches the **High** impact: *Mempool/gateway/RPC admission accepts invalid transactions (transactions that violate the fee escalation admission policy) before sequencing.*

---

### Likelihood Explanation

The trigger is fully unprivileged: any account that has a transaction in the mempool can submit a replacement. The crafted replacement is a well-formed V3 Starknet transaction; no special permissions or privileged access are required. The only constraint is that `l1_gas.max_price_per_unit` must be at least the current block's L1 gas price to pass blockifier validation, which is a weak lower bound easily satisfied while still being far below the original transaction's L1 price commitment.

---

### Recommendation

1. **Extend `TransactionReference` and `ValidationArgs`** to carry `l1_gas_max_price` and `l1_data_gas_max_price` alongside `max_l2_gas_price`.

2. **Update `should_replace_tx`** to require that the total committed fee of the replacement — computed as `tip·l2_amount + max_l2_gas_price·l2_amount + l1_gas_price·l1_amount + l1_data_gas_price·l1_data_amount` (or at minimum each price dimension individually) — is increased by the required escalation percentage over the existing transaction.

3. **Update `ValidationArgs::new`** and `From<&AddTransactionArgs> for ValidationArgs` to extract all three price bounds from `AllResourceBounds`.

4. **Remove or resolve the TODO** in `validate_tx_l2_gas_price_within_threshold` to also enforce L1 and L1 data gas price thresholds at the gateway stateful validation layer.

---

### Proof of Concept

```
Existing tx in mempool:
  address = 0xABC, nonce = 5
  tip = 100
  l2_gas.max_price_per_unit = 100
  l1_gas.max_price_per_unit = 50_000   ← large L1 commitment
  l1_data_gas.max_price_per_unit = 50_000

fee_escalation_percentage = 10
current block: l1_gas_price = 1, l1_data_gas_price = 1

Replacement tx submitted by same sender:
  address = 0xABC, nonce = 5
  tip = 110                             ← +10%, passes increased_enough()
  l2_gas.max_price_per_unit = 110       ← +10%, passes increased_enough()
  l1_gas.max_price_per_unit = 1         ← just above block price, passes blockifier check_fee_bounds
  l1_data_gas.max_price_per_unit = 1    ← just above block price, passes blockifier check_fee_bounds

should_replace_tx result: true  (only tip and max_l2_gas_price are compared)
blockifier check_fee_bounds result: Ok (1 >= 1 for both L1 resources)

Outcome: replacement admitted; original transaction with 50_000× higher L1 price commitment evicted.
```

`TransactionReference::new` extracts only `l2_gas.max_price_per_unit` at line 1112, so the L1 price reduction is invisible to every subsequent escalation comparison. [2](#0-1) [4](#0-3) [9](#0-8)

### Citations

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L411-443)
```rust
    fn add_tx_validations(
        &mut self,
        tx_reference: TransactionReference,
        tx: &InternalRpcTransaction,
        account_nonce: Nonce,
    ) -> MempoolResult<()> {
        self.validate_incoming_tx(tx_reference, account_nonce)?;
        let replaced_tx_reference = self.validate_fee_escalation(tx_reference)?;

        // The replaced transaction is still pooled, so its bytes still count toward
        // `size_in_bytes()`. Credit what its removal will free: a same-size bump nets to zero (no
        // overflow handling), and a larger replacement only needs room for the delta, consistent
        // with how a fresh next-nonce transaction is treated. The removal happens only after
        // capacity is confirmed below, so a rejected incoming transaction never strands the
        // account.
        let freed_bytes = replaced_tx_reference.map_or(0, |reference| {
            self.tx_pool
                .get_by_tx_hash(reference.tx_hash)
                .expect("Replacement target from pool must exist.")
                .total_bytes()
        });

        if self.exceeds_capacity(tx, freed_bytes) {
            self.handle_capacity_overflow(tx, account_nonce, freed_bytes)?;
        }

        // Capacity is confirmed: this is the final, infallible mutation before the incoming
        // transaction is inserted by the caller.
        if let Some(existing_tx_reference) = replaced_tx_reference {
            self.remove_replaced_tx(existing_tx_reference);
        }

        Ok(())
```

**File:** crates/apollo_mempool/src/mempool.rs (L807-819)
```rust
    fn should_replace_tx(
        &self,
        existing_tx: &TransactionReference,
        incoming_tx: &TransactionReference,
    ) -> bool {
        let [existing_tip, incoming_tip] =
            [existing_tx, incoming_tx].map(|tx| u128::from(tx.tip.0));
        let [existing_max_l2_gas_price, incoming_max_l2_gas_price] =
            [existing_tx, incoming_tx].map(|tx| tx.max_l2_gas_price.0);

        self.increased_enough(existing_tip, incoming_tip)
            && self.increased_enough(existing_max_l2_gas_price, incoming_max_l2_gas_price)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L1096-1114)
```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReference {
    pub address: ContractAddress,
    pub nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}

impl TransactionReference {
    pub fn new(tx: &InternalRpcTransaction) -> Self {
        TransactionReference {
            address: tx.contract_address(),
            nonce: tx.nonce(),
            tx_hash: tx.tx_hash(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().l2_gas.max_price_per_unit,
        }
    }
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L49-69)
```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}

impl ValidationArgs {
    pub fn new(tx: &AccountTransaction, account_nonce: Nonce) -> Self {
        Self {
            address: tx.sender_address(),
            account_nonce,
            tx_hash: tx.tx_hash(),
            tx_nonce: tx.nonce(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
        }
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-390)
```rust
    // TODO(Arni): Consider running this validation for all gas prices.
    fn validate_tx_l2_gas_price_within_threshold(
        &self,
        tx_resource_bounds: ValidResourceBounds,
        previous_block_l2_gas_price: NonzeroGasPrice,
    ) -> StatefulTransactionValidatorResult<()> {
        match tx_resource_bounds {
            ValidResourceBounds::AllResources(tx_resource_bounds) => {
                let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
                if tx_l2_gas_price.0 < threshold {
                    return Err(StarknetError {
                        // We didn't have this kind of an error.
                        code: StarknetErrorCode::UnknownErrorCode(
                            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
                        ),
                        message: format!(
                            "Transaction L2 gas price {tx_l2_gas_price} is below the required \
                             threshold {threshold}.",
                        ),
                    });
                }
            }
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
        }
        Ok(())
    }
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/transaction_impls.cairo (L95-101)
```text
    tempvar l1_gas_bounds: ResourceBounds = resource_bounds[L1_GAS_INDEX];
    tempvar l2_gas_bounds: ResourceBounds = resource_bounds[L2_GAS_INDEX];
    tempvar l1_data_gas_bounds = resource_bounds[L1_DATA_GAS_INDEX];

    return l1_gas_bounds.max_amount * l1_gas_bounds.max_price_per_unit + l2_gas_bounds.max_amount *
        (l2_gas_bounds.max_price_per_unit + tx_info.tip) + l1_data_gas_bounds.max_amount *
        l1_data_gas_bounds.max_price_per_unit;
```
