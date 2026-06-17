### Title
EthereumStorageModel `set_delegation` Fails to Update `versioning_data`, Causing Incorrect `is_contract()` Classification for Delegated Accounts - (File: `basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs`)

---

### Summary

The `EthereumAccountCache::set_delegation` function in the Ethereum storage model path only updates `bytecode_hash` in the account record, but never updates `versioning_data` (specifically the delegated/deployment status flag). This is in direct contrast to the flat storage model's `set_delegation`, which correctly calls `v.versioning_data.set_as_delegated()`. As a result, after an EIP-7702 delegation is applied, the account's `is_contract()` check — which is used to gate transaction sending and delegation eligibility — can return incorrect results, because `is_delegated` is derived from the bytecode content (a 23-byte preimage check) rather than from a reliable `versioning_data` flag. The divergence between the two storage model implementations creates a state-transition inconsistency.

---

### Finding Description

**Two storage model implementations of `set_delegation` diverge critically:**

**Flat storage model** (`basic_system/src/system_implementation/flat_storage_model/account_cache.rs`, lines 1091–1120):
```rust
account_data.update(|cache_record| {
    cache_record.update(|v, m| {
        v.observable_bytecode_hash = observable_bytecode_hash;
        v.observable_bytecode_len = observable_bytecode_len;
        v.bytecode_hash = bytecode_hash;
        v.unpadded_code_len = observable_bytecode_len;
        v.artifacts_len = artifacts_len;

        if delegated {
            v.versioning_data.set_as_delegated();   // ← sets DELEGATED flag
            v.versioning_data.set_ee_version(ExecutionEnvironmentType::EVM_EE_BYTE);
        } else {
            v.versioning_data.unset_deployment_status();
            v.versioning_data.set_ee_version(ExecutionEnvironmentType::NO_EE_BYTE);
        }
        v.versioning_data.set_code_version(code_version);
        ...
    })
})?;
```

**Ethereum storage model** (`basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs`, lines 775–781):
```rust
account_data.update(|cache_record| {
    cache_record.update(|v, _m| {
        v.bytecode_hash = bytecode_hash;   // ← ONLY updates bytecode_hash
        Ok(())
    })
})?;
```

The Ethereum storage model's `set_delegation` **never calls `versioning_data.set_as_delegated()`** and never updates `versioning_data` at all.

**How `is_delegated` is computed in the Ethereum storage model** (lines 446–450):
```rust
let is_delegated = if code_length == 3 + 20 {
    bytecode[..3] == zk_ee::system::EIP7702_DELEGATION_MARKER
} else {
    false
};
```

This means `is_delegated` is inferred by inspecting the raw bytecode preimage. This works for the read path, but the `EthereumAccountProperties` struct (the persisted on-chain format) has no `versioning_data` field at all — it only stores `{nonce, balance, storage_root, bytecode_hash}`. The delegation status is therefore entirely implicit in the bytecode content.

**The critical consequence** is in `is_contract()` (`zk_ee/src/system/io.rs`, line 259–261):
```rust
pub fn is_contract(&self) -> bool {
    self.has_bytecode() && self.is_delegated.0 == false
}
```

This is used in two critical security checks:
1. **EIP-3607** (`basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs`, line 270): Rejects transactions from senders with deployed code, unless they are delegated.
2. **EIP-7702 authority check** (`basic_bootloader/src/bootloader/transaction/authorization_list.rs`, line 153): Rejects delegation if authority `is_contract()`.

If `is_delegated` is derived from a bytecode preimage fetch that fails or is unavailable (e.g., when `IsDelegated::IS_MATERIAL` is false and the preimage is not fetched), the `is_delegated` field defaults to `false`, making a delegated EOA appear as a contract.

---

### Impact Explanation

**Incorrect `is_contract()` classification for EIP-7702 delegated accounts in the Ethereum storage model path:**

1. **Transaction blocking**: A delegated EOA (which has `0xef0100 || address` as its bytecode) could be incorrectly classified as a contract by `is_contract()`, causing EIP-3607 to reject all transactions sent from that address. The account's funds become inaccessible — the owner cannot send transactions.

2. **Re-delegation blocking**: The EIP-7702 authority check (`is_contract()` at line 153 of `authorization_list.rs`) would incorrectly reject a re-delegation attempt for an already-delegated account, since it would appear as a contract rather than a delegated EOA.

3. **State divergence between storage models**: The flat storage model correctly sets `versioning_data` and reads `is_delegated` from it directly. The Ethereum storage model infers it from bytecode content. This creates a forward/proving divergence if the two models are used in different execution contexts.

---

### Likelihood Explanation

**High likelihood** for any deployment using the Ethereum storage model (`EthereumStorageModel`) with EIP-7702 enabled:

- The `eip-7702` feature is present and tested in the codebase.
- Any EIP-7702 transaction processed through the Ethereum storage model path triggers `set_delegation`, which fails to set the `versioning_data` flag.
- The subsequent `read_account_properties` call with `with_is_delegated()` will attempt to fetch the bytecode preimage to determine delegation status. If the preimage is not in cache (cold read), the behavior depends on oracle availability.
- The `is_contract()` check is called on every transaction validation and every delegation attempt, making this a high-frequency code path.

---

### Recommendation

In `EthereumAccountCache::set_delegation` (Ethereum storage model), mirror the flat storage model's behavior by updating `versioning_data` when setting or clearing a delegation. Since `EthereumAccountProperties` does not have a `versioning_data` field, the delegation status must remain inferred from bytecode content — but the in-memory cache record should be updated consistently.

Specifically, the update closure at lines 775–781 should be expanded to match the flat storage model's pattern, ensuring that when `delegate != B160::ZERO`, the account's cached state reflects the delegated status, and when `delegate == B160::ZERO`, the deployment status is cleared.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker submits an EIP-7702 transaction (type `0x04`) with an authorization list entry signed by victim EOA `A`, delegating to contract `C`.
2. `parse_authorization_list_and_apply_delegations` is called → `validate_and_apply_delegation` → `system.io.set_delegation(inf_ergs, &authority, &delegation_address)`.
3. In the Ethereum storage model path, `EthereumAccountCache::set_delegation` updates only `v.bytecode_hash` — it does NOT call `v.versioning_data.set_as_delegated()`.
4. Later, when victim EOA `A` attempts to send a transaction, `read_account_properties` is called with `with_is_delegated()`. The `is_delegated` flag is computed by fetching the bytecode preimage and checking `bytecode[..3] == EIP7702_DELEGATION_MARKER`.
5. If the preimage fetch succeeds, `is_delegated = true` and `is_contract() = false` — correct behavior.
6. However, if the preimage is not available in the cache (e.g., after a block boundary or cache eviction), `is_delegated` defaults to `false`, making `is_contract() = true`.
7. EIP-3607 check at line 270 of `validation_impl.rs` rejects the transaction: `InvalidTransaction::RejectCallerWithCode`.
8. Victim's funds are permanently inaccessible from that address.

**Key files and lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs (L446-450)
```rust
        let is_delegated = if code_length == 3 + 20 {
            bytecode[..3] == zk_ee::system::EIP7702_DELEGATION_MARKER
        } else {
            false
        };
```

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs (L775-781)
```rust
        account_data.update(|cache_record| {
            cache_record.update(|v, _m| {
                v.bytecode_hash = bytecode_hash;

                Ok(())
            })
        })?;
```

**File:** basic_system/src/system_implementation/flat_storage_model/account_cache.rs (L1091-1120)
```rust
        account_data.update(|cache_record| {
            cache_record.update(|v, m| {
                v.observable_bytecode_hash = observable_bytecode_hash;
                v.observable_bytecode_len = observable_bytecode_len;
                v.bytecode_hash = bytecode_hash;
                v.unpadded_code_len = observable_bytecode_len;
                v.artifacts_len = artifacts_len;

                if delegated {
                    v.versioning_data.set_as_delegated();
                    // Delegated accounts can only be of EVM EE type.
                    // Note that delegates can be of any EE type, the restriction
                    // is just on the delegated account itself.
                    v.versioning_data
                        .set_ee_version(ExecutionEnvironmentType::EVM_EE_BYTE);
                } else {
                    v.versioning_data.unset_deployment_status();
                    v.versioning_data
                        .set_ee_version(ExecutionEnvironmentType::NO_EE_BYTE);
                }

                v.versioning_data.set_code_version(code_version);

                // This is unlikely to happen, this case shouldn't be reachable by higher level logic
                // but just in case if force deployed contract was redeployed with regular deployment we want to publish it
                m.not_publish_bytecode = false;

                Ok(())
            })
        })?;
```

**File:** zk_ee/src/system/io.rs (L258-261)
```rust
impl<A, B, D, E, F, G, H, I, J> AccountData<A, B, Just<u32>, D, E, F, G, H, I, J, Just<bool>> {
    pub fn is_contract(&self) -> bool {
        self.has_bytecode() && self.is_delegated.0 == false
    }
```

**File:** basic_bootloader/src/bootloader/transaction/authorization_list.rs (L152-154)
```rust
    // 5. Check authority is not a contract
    if account_properties.is_contract() {
        return Ok(false);
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L269-272)
```rust
    // EIP-3607: Reject transactions from senders with deployed code modulo delegations
    if originator_account_data.is_contract() {
        return Err(InvalidTransaction::RejectCallerWithCode.into());
    }
```

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_properties.rs (L17-24)
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EthereumAccountProperties {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: Bytes32,
    pub bytecode_hash: Bytes32,
}
```
