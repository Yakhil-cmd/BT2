### Title
Unprotected Legacy Transactions (Pre-EIP-155) Accepted Without Chain ID Binding, Enabling Cross-Chain Replay - (File: `basic_bootloader/src/bootloader/transaction/rlp_encoded/mod.rs`)

### Summary
ZKsync OS explicitly accepts pre-EIP-155 legacy transactions (those with `v = 27` or `v = 28`) without any chain ID check. Because the signing hash for such transactions contains no chain ID, a transaction signed on Ethereum mainnet (or any other EVM chain) can be replayed verbatim on ZKsync OS, and vice versa.

### Finding Description
In `RlpEncodedTxInner::parse_and_compute_signed_hash`, after parsing a legacy transaction, the code branches on whether the signature is EIP-155-protected: [1](#0-0) 

The `is_eip155()` predicate is: [2](#0-1) 

When `v == 27` or `v == 28`, `is_eip155()` returns `false`, the transaction is classified as `Self::Legacy`, and the signing hash is computed over only the 6-field payload — **with no chain ID included**: [3](#0-2) 

There is no subsequent rejection of the `Self::Legacy` variant anywhere in the transaction processing pipeline. The `chain_id()` accessor on `RlpEncodedTransaction` returns `None` for this variant, confirming it is treated as chain-agnostic: [4](#0-3) 

By contrast, all typed transactions (EIP-2930, EIP-1559, EIP-4844, EIP-7702) enforce `tx.chain_id != expected_chain_id` and return `InvalidChainId` on mismatch: [5](#0-4) 

### Impact Explanation
Any pre-EIP-155 legacy transaction that was signed for Ethereum mainnet (or any other EVM-compatible chain) with `v ∈ {27, 28}` produces an identical signing hash on ZKsync OS. If the originating address holds funds on ZKsync OS, an attacker can submit that transaction to ZKsync OS and it will pass signature verification and execute. This enables:

- **Cross-chain replay**: Ethereum mainnet transactions replayed on ZKsync OS (and vice versa), draining user funds.
- **State-transition correctness violation**: The bootloader accepts and executes transactions that were never authorized for ZKsync OS.

### Likelihood Explanation
Pre-EIP-155 transactions are still broadcast on Ethereum mainnet and other EVM chains (e.g., by legacy wallets, hardware wallets with old firmware, or contracts that generate raw transactions). Any such transaction whose sender also holds a balance on ZKsync OS is immediately exploitable by any observer of the public mempool. No privileged access is required — the attacker only needs to observe a pre-EIP-155 transaction on another chain and re-submit it to ZKsync OS.

### Recommendation
Reject unprotected legacy transactions (those where `is_eip155()` returns `false`) at the parse/validation stage. The simplest fix is to return `InvalidTransaction::InvalidChainId` (or a dedicated `UnprotectedLegacyTx` error) when the `Self::Legacy` variant is produced, rather than allowing it to proceed. If pre-EIP-155 compatibility is intentionally required, the operator must accept the replay risk and document it explicitly.

### Proof of Concept
1. On Ethereum mainnet, broadcast a legacy transaction with `v = 27` (no EIP-155 protection). Record the raw RLP bytes.
2. Submit those identical raw bytes to ZKsync OS as an L2 transaction.
3. In `parse_and_compute_signed_hash`, `is_eip155()` returns `false` → variant `Self::Legacy` is produced.
4. The signing hash is computed over the 6-field payload only (no chain ID) — identical to the Ethereum signing hash.
5. ECDSA recovery succeeds, `from` matches the Ethereum sender.
6. If that address has a balance on ZKsync OS, the transaction executes, transferring funds the sender never authorized on ZKsync OS.

The relevant code path is: [1](#0-0) [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/mod.rs (L65-67)
```rust
                    if tx.chain_id != expected_chain_id {
                        return Err(InvalidTransaction::InvalidChainId.into());
                    }
```

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/mod.rs (L119-134)
```rust
        } else {
            // Legacy path
            let (tx, sig_data, sig_hash) =
                LegacyPayloadParser::try_parse_and_hash_for_signature_verification(
                    input,
                    expected_chain_id,
                )?;

            let tx = if sig_data.is_eip155() {
                Self::LegacyWithEIP155(tx, sig_data)
            } else {
                Self::Legacy(tx, sig_data)
            };

            Ok((tx, sig_hash))
        }
```

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/legacy_tx.rs (L89-115)
```rust
        let sig_hash: Bytes32 = if legacy_signature.is_eip155() == false {
            // Unprotected legacy
            let mut hasher = crypto::sha3::Keccak256::new();
            apply_list_concatenation_encoding_to_hash(inner_slice.len() as u32, &mut hasher);
            hasher.update(inner_slice);
            hasher.finalize_reset().into()
        } else {
            // EIP-155 protected legacy: v must match 35 + 2*chainId (+ {0,1})
            let min_v = U256::from(35) + U256::from(expected_chain_id) * U256::from(2);
            if !(legacy_signature.v == min_v || legacy_signature.v == min_v + U256::ONE) {
                return Err(InvalidTransaction::InvalidEncoding.into());
            }

            // Compute signing hash over the 6-field payload plus chainId and two empty strings.
            let chain_id = expected_chain_id;
            let chain_id_encoding_len = u64_encoding_len(chain_id);

            let mut hasher = crypto::sha3::Keccak256::new();
            apply_list_concatenation_encoding_to_hash(
                (inner_slice.len() + chain_id_encoding_len + 2) as u32, // 0x80, 0x80 for r/s
                &mut hasher,
            );
            hasher.update(inner_slice);
            apply_u64_encoding_to_hash(chain_id, &mut hasher);
            hasher.update(&[0x80, 0x80]);
            hasher.finalize_reset().into()
        };
```

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/legacy_tx.rs (L128-131)
```rust
impl<'a> LegacySignatureData<'a> {
    pub fn is_eip155(&self) -> bool {
        self.v != 27 && self.v != 28
    }
```

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction.rs (L82-87)
```rust
    pub fn chain_id(&self) -> Option<u64> {
        match &self.inner {
            RlpEncodedTxInner::Legacy(_, _) => None,
            _ => Some(self.chain_id),
        }
    }
```
