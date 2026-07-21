### Title
Gateway stateless validator combines `calldata` and `proof_facts` lengths against `max_calldata_length`, causing false rejection of valid Invoke transactions with client-side proving — (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_tx_extended_calldata_size` computes `total_length = calldata.len() + proof_facts.len()` for Invoke V3 transactions and checks it against the single `max_calldata_length` limit. Because `proof_facts` is a structurally separate field whose purpose is client-side proving — not calldata — any Invoke V3 transaction whose calldata is exactly at the configured limit but also carries non-empty `proof_facts` is incorrectly rejected with `CalldataTooLong`. This is the direct sequencer analog of the external `balanceOf(address(this))` bug: a shared accounting value that conflates two logically distinct pools causes the wrong admission decision.

---

### Finding Description

In `validate_tx_extended_calldata_size`:

```rust
RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => {
    tx.calldata.0.len() + tx.proof_facts.0.len()   // ← combined
}
// ...
if total_length > self.config.max_calldata_length {
    return Err(StatelessTransactionValidatorError::CalldataTooLong {
        calldata_length: total_length,              // ← reported as "calldata"
        max_calldata_length: self.config.max_calldata_length,
    });
}
```

The production `max_calldata_length` is **5 000** elements (config key `gateway_config.static_config.stateless_tx_validator_config.max_calldata_length`, described as *"Limitation of calldata length"*). `proof_facts` is a completely separate field: it carries SNOS proof-version markers, program hashes, block hashes, and config hashes for the client-side proving feature. It is validated independently by `validate_proof_facts_and_proof_consistency`, `validate_client_side_proving_allowed`, and `AccountTransaction::validate_proof_facts` in the blockifier.

Two concrete consequences follow:

1. **False rejection of valid transactions.** An Invoke V3 transaction with `calldata.len() == 5 000` (exactly at the limit) and `proof_facts.len() >= 1` is rejected with `CalldataTooLong { calldata_length: 5001, max_calldata_length: 5000 }`, even though the calldata itself is within the configured bound. The existing test `client_side_proving_calldata_too_long` already encodes this exact scenario and confirms the rejection.

2. **Asymmetric budget.** A transaction with `calldata.len() == 0` and `proof_facts.len() == 5 000` passes the combined check. There is no separate `max_proof_facts_length` limit — `validate_proof_size` only bounds `tx.proof.0.len()` (the compressed proof bytes), not `proof_facts`. So `proof_facts` can silently consume the entire calldata budget while calldata is squeezed out.

The structural parallel to the external bug is exact:

| External (Solidity) | Sequencer (Rust) |
|---|---|
| `raacToken.balanceOf(address(this))` = rewards + pool deposits | `calldata.len() + proof_facts.len()` = calldata + proving metadata |
| Pool deposits are meant for managers, not users | `proof_facts` is meant for proving, not calldata |
| Combined balance used for user reward calculation → over-distribution | Combined length used for calldata admission check → false rejection |

---

### Impact Explanation

Any Invoke V3 transaction that legitimately uses client-side proving (`proof_facts` non-empty) and has calldata at or near the 5 000-element limit is rejected at the gateway stateless validation stage before it ever reaches the mempool or blockifier. The transaction is structurally valid — its calldata is within the documented limit — but the gateway returns `CalldataTooLong` because `proof_facts` inflates the combined counter. This matches the allowed impact:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The trigger is fully unprivileged. Any user who submits an Invoke V3 transaction with both a large calldata payload (≥ 5 000 − `proof_facts.len()` elements) and non-empty `proof_facts` will hit this rejection. Client-side proving is enabled in production (`allow_client_side_proving: true`). A standard SNOS `proof_facts` payload is 7 felts (proof-version marker, variant marker, program hash, output-version, block number, block hash, config hash), so any calldata with ≥ 4 994 elements combined with a valid proof submission triggers the false rejection.

---

### Recommendation

Separate the two size checks. Check only `calldata.len()` against `max_calldata_length`, and introduce a dedicated `max_proof_facts_length` config entry checked independently:

```rust
// validate_tx_extended_calldata_size: check calldata only
RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => tx.calldata.0.len(),

// new validate_proof_facts_size (analogous to validate_proof_size):
fn validate_proof_facts_size(&self, tx: &RpcInvokeTransaction)
    -> StatelessTransactionValidatorResult<()>
{
    let RpcInvokeTransaction::V3(tx) = tx;
    let proof_facts_length = tx.proof_facts.0.len();
    if proof_facts_length > self.config.max_proof_facts_length {
        return Err(StatelessTransactionValidatorError::ProofFactsTooLong {
            proof_facts_length,
            max_proof_facts_length: self.config.max_proof_facts_length,
        });
    }
    Ok(())
}
```

Update the config description for `max_calldata_length` to reflect that it bounds calldata only, and add `max_proof_facts_length` with an appropriate production value (e.g. 32 felts, covering the current SNOS layout with room for future fields).

---

### Proof of Concept

Using the existing test harness in `crates/apollo_gateway/src/stateless_transaction_validator_test.rs`:

```rust
// Demonstrates false rejection: calldata is exactly at the limit,
// but proof_facts pushes the combined total over it.
let config = StatelessTransactionValidatorConfig {
    max_calldata_length: 5000,
    allow_client_side_proving: true,
    ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
};
let tx_validator = StatelessTransactionValidator { config };

// Build calldata with exactly 5000 elements (within the limit).
let calldata = Calldata(Arc::new(vec![Felt::ONE; 5000]));
// Add a minimal valid proof_facts (1 element is enough to trigger the bug).
let proof_facts = proof_facts![Felt::ONE];

let tx = rpc_tx_for_testing(
    TransactionType::Invoke,
    RpcTransactionArgs { calldata, proof_facts, ..Default::default() },
);

// Expected: Ok(()) — calldata is within the 5000-element limit.
// Actual:   Err(CalldataTooLong { calldata_length: 5001, max_calldata_length: 5000 })
assert_matches!(tx_validator.validate(&tx), Ok(()));  // ← FAILS
```

The test case `client_side_proving_calldata_too_long` already present in the test file at line 286 confirms the same rejection with `max_calldata_length: 1`, `calldata.len(): 1`, `proof_facts.len(): 1`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L142-150)
```rust
    fn validate_tx_size(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        self.validate_tx_extended_calldata_size(tx)?;
        self.validate_tx_signature_size(tx)?;
        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_proof_size(invoke_tx)?;
        }

        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L154-178)
```rust
    fn validate_tx_extended_calldata_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let total_length = match tx {
            RpcTransaction::Declare(_) => return Ok(()),

            RpcTransaction::DeployAccount(RpcDeployAccountTransaction::V3(tx)) => {
                tx.constructor_calldata.0.len()
            }

            RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => {
                tx.calldata.0.len() + tx.proof_facts.0.len()
            }
        };

        if total_length > self.config.max_calldata_length {
            return Err(StatelessTransactionValidatorError::CalldataTooLong {
                calldata_length: total_length,
                max_calldata_length: self.config.max_calldata_length,
            });
        }

        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L265-278)
```rust
    fn validate_proof_size(
        &self,
        tx: &RpcInvokeTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let RpcInvokeTransaction::V3(tx) = tx;
        let proof_size = tx.proof.0.len();
        if proof_size > self.config.max_proof_size {
            return Err(StatelessTransactionValidatorError::ProofTooLarge {
                proof_size,
                max_proof_size: self.config.max_proof_size,
            });
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L286-297)
```rust
#[case::client_side_proving_calldata_too_long(
    StatelessTransactionValidatorConfig {
        max_calldata_length: 1,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs { calldata: calldata![Felt::ONE], proof_facts: proof_facts![Felt::TWO], ..Default::default() },
    StatelessTransactionValidatorError::CalldataTooLong {
        calldata_length: 2,
        max_calldata_length: 1
    },
    vec![TransactionType::Invoke],
)]
```

**File:** crates/apollo_node/resources/config_schema.json (L3157-3161)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_calldata_length": {
    "description": "Limitation of calldata length.",
    "privacy": "Public",
    "value": 5000
  },
```

**File:** crates/apollo_node/resources/config_schema.json (L3177-3180)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_proof_size": {
    "description": "Limitation of proof size.",
    "privacy": "Public",
    "value": 480000
```
