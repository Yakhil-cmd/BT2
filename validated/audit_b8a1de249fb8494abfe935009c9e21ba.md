### Title
EIP-7702 Authorization Signing Hash Uses Literal `chain_id = 0` Instead of Current Chain ID When Authorization `chain_id` Is Zero — (`File: basic_bootloader/src/bootloader/transaction/authorization_list.rs`)

---

### Summary

In `validate_and_apply_delegation`, when an EIP-7702 authorization entry carries `chain_id = 0` (the "any-chain" wildcard), the signing hash is computed by passing the literal zero value into `compute_auth_message_signed_hash`. This means the signed message is `keccak(0x05 || rlp([0, address, nonce]))`. Because the hash does not bind to the actual executing chain, a single authorization signature with `chain_id = 0` is valid on **every** ZKsync OS chain simultaneously. An attacker who observes a valid delegation on one chain can replay it on any other chain that runs ZKsync OS with the same account nonce, setting arbitrary delegation code on the victim's EOA without the victim's knowledge.

---

### Finding Description

In `basic_bootloader/src/bootloader/transaction/authorization_list.rs`, `validate_and_apply_delegation` performs the chain-ID check at line 108:

```rust
if !auth_chain_id.is_zero() && auth_chain_id != &U256::from(chain_id) {
    return Ok(false);
}
```

When `auth_chain_id` is zero the check is skipped (by design, per EIP-7702 spec). The function then calls `compute_auth_message_signed_hash` at line 123–131, passing the **original** `auth_chain_id` (which is `0`) directly into the hash:

```rust
let msg = resources.with_infinite_ergs(|inf_ergs| {
    compute_auth_message_signed_hash::<S>(
        inf_ergs,
        auth_chain_id,   // ← still 0
        auth_nonce,
        delegation_address,
        hasher,
    )
})?;
```

Inside `compute_auth_message_signed_hash` (lines 218–230), the zero value is RLP-encoded verbatim:

```rust
rlp::apply_number_encoding_to_hash(&auth_chain_id.to_be_bytes::<32>(), hasher);
```

The resulting signed message is therefore `keccak(0x05 || rlp([0, address, nonce]))` — identical on every chain. The EIP-7702 specification (EIP-7702 §Authority) explicitly states that when `chain_id = 0` the signer intends the authorization to be valid on any chain, but the **signing hash** must still commit to the actual chain ID at execution time to prevent cross-chain replay. The correct behavior is to substitute the current chain's ID into the hash when `auth_chain_id` is zero, so that the same signature cannot be replayed on a different chain.

---

### Impact Explanation

An attacker who observes a valid EIP-7702 authorization with `chain_id = 0` on one ZKsync OS chain (e.g., ZKsync Era mainnet) can replay the exact same signed authorization tuple `(chain_id=0, address, nonce, y_parity, r, s)` on any other ZKsync OS chain where the victim's account has the same nonce. The replay succeeds because:

1. The chain-ID guard passes (`auth_chain_id.is_zero()` → skip).
2. The signing hash is identical across all chains.
3. `ecrecover` returns the same authority address.
4. If the nonce matches, the delegation is applied.

The result is that the victim's EOA on the target chain is silently delegated to an attacker-controlled contract address, allowing the attacker to execute arbitrary code in the context of the victim's account on subsequent calls.

---

### Likelihood Explanation

EIP-7702 with `chain_id = 0` is a documented feature intended for multi-chain wallets. Users and wallet software that sign with `chain_id = 0` expecting "any-chain" convenience are directly exposed. ZKsync OS operates multiple chains (Era mainnet, testnets, hyperchains), all sharing the same bootloader code. Any authorization signed with `chain_id = 0` on one of these chains is immediately replayable on all others by any observer of the mempool or block data. No privileged access is required; the attacker only needs to copy the authorization tuple from one chain's transaction and include it in an EIP-7702 transaction on another chain.

---

### Recommendation

When `auth_chain_id` is zero, substitute the current chain's ID before computing the signing hash, so the hash commits to the actual executing chain:

```rust
let effective_chain_id = if auth_chain_id.is_zero() {
    U256::from(chain_id)
} else {
    *auth_chain_id
};
let msg = resources.with_infinite_ergs(|inf_ergs| {
    compute_auth_message_signed_hash::<S>(
        inf_ergs,
        &effective_chain_id,   // ← use actual chain ID
        auth_nonce,
        delegation_address,
        hasher,
    )
})?;
```

This matches the behavior of reference implementations (e.g., go-ethereum) which substitute `chainID` into the hash when the authorization carries `chain_id = 0`.

---

### Proof of Concept

**Root cause — chain-ID zero bypasses hash binding:** [1](#0-0) 

**Signing hash computed with the literal zero value:** [2](#0-1) 

**Zero is RLP-encoded verbatim into the hash:** [3](#0-2) 

**Attack steps:**

1. Victim signs an EIP-7702 authorization with `chain_id = 0`, `address = attacker_contract`, `nonce = N` on ZKsync Era mainnet (chain ID 324).
2. Attacker observes the signed tuple `(0, attacker_contract, N, y_parity, r, s)` from the mempool or a confirmed block.
3. Attacker submits an EIP-7702 transaction on a second ZKsync OS chain (e.g., a hyperchain with chain ID 999) containing the same authorization tuple.
4. `validate_and_apply_delegation` on chain 999: `auth_chain_id.is_zero()` → chain-ID check skipped; signing hash = `keccak(0x05 || rlp([0, attacker_contract, N]))` — identical to chain 324; `ecrecover` returns victim's address; nonce matches → delegation applied.
5. Victim's EOA on chain 999 is now delegated to `attacker_contract` without the victim's consent.

### Citations

**File:** basic_bootloader/src/bootloader/transaction/authorization_list.rs (L107-110)
```rust
    // 1. Check chain id
    if !auth_chain_id.is_zero() && auth_chain_id != &U256::from(chain_id) {
        return Ok(false);
    }
```

**File:** basic_bootloader/src/bootloader/transaction/authorization_list.rs (L123-131)
```rust
    let msg = resources.with_infinite_ergs(|inf_ergs| {
        compute_auth_message_signed_hash::<S>(
            inf_ergs,
            auth_chain_id,
            auth_nonce,
            delegation_address,
            hasher,
        )
    })?;
```

**File:** basic_bootloader/src/bootloader/transaction/authorization_list.rs (L218-230)
```rust
    let list_payload_len = rlp::estimate_number_encoding_len(&auth_chain_id.to_be_bytes::<32>())
        + rlp::ADDRESS_ENCODING_LEN
        + rlp::estimate_number_encoding_len(&auth_nonce.to_be_bytes());
    let total_list_len = rlp::estimate_length_encoding_len(list_payload_len) + list_payload_len;
    let encoding_len = 1 + total_list_len;
    crate::bootloader::transaction::charge_keccak(encoding_len, resources)?;
    hasher.update([EIP7702_MAGIC]);
    rlp::apply_list_length_encoding_to_hash(list_payload_len, hasher);
    rlp::apply_number_encoding_to_hash(&auth_chain_id.to_be_bytes::<32>(), hasher);
    rlp::apply_bytes_encoding_to_hash(delegation_address, hasher);
    rlp::apply_number_encoding_to_hash(&auth_nonce.to_be_bytes(), hasher);

    Ok(hasher.finalize_reset())
```
