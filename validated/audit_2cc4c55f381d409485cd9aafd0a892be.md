### Title
Cross-Chain Replay of Unprotected Legacy Transactions Due to Missing Chain-ID Binding in Signing Hash - (File: `basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/legacy_tx.rs`)

---

### Summary

ZKsync OS accepts pre-EIP-155 ("unprotected") legacy transactions whose signing hash contains no chain-ID. Because the hash is identical on every EVM-compatible chain, any unprotected legacy transaction signed on Ethereum mainnet (or any other EVM chain) can be replayed verbatim on ZKsync OS whenever the sender's nonce matches, enabling unauthorized fund transfers without the victim's consent for this chain.

---

### Finding Description

**Root cause — missing domain separation in the signing hash for unprotected legacy transactions.**

In `LegacyPayloadParser::try_parse_and_hash_for_signature_verification`, the code branches on whether the signature is EIP-155-protected:

```rust
let sig_hash: Bytes32 = if legacy_signature.is_eip155() == false {
    // Unprotected legacy
    let mut hasher = crypto::sha3::Keccak256::new();
    apply_list_concatenation_encoding_to_hash(inner_slice.len() as u32, &mut hasher);
    hasher.update(inner_slice);   // only [nonce, gasPrice, gasLimit, to, value, data]
    hasher.finalize_reset().into()
} else {
    // EIP-155 protected: chain_id is mixed into the hash
    ...
    apply_u64_encoding_to_hash(chain_id, &mut hasher);
    ...
};
``` [1](#0-0) 

`is_eip155()` returns `false` when `v == 27` or `v == 28`: [2](#0-1) 

When the unprotected branch is taken, the `expected_chain_id` argument is completely ignored and the signing hash is `keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data]))` — identical on every EVM chain.

In `RlpEncodedTxInner::parse_and_compute_signed_hash`, the unprotected variant is stored as `Self::Legacy` with no chain-ID validation:

```rust
let tx = if sig_data.is_eip155() {
    Self::LegacyWithEIP155(tx, sig_data)
} else {
    Self::Legacy(tx, sig_data)   // no chain_id check performed
};
Ok((tx, sig_hash))
``` [3](#0-2) 

The `chain_id()` accessor confirms that `Legacy` carries no chain binding:

```rust
pub fn chain_id(&self) -> Option<u64> {
    match &self.inner {
        RlpEncodedTxInner::Legacy(_, _) => None,   // no chain ID
        _ => Some(self.chain_id),
    }
}
``` [4](#0-3) 

The proving execution config (`BasicBootloaderProvingExecutionConfig`) has `VALIDATE_EOA_SIGNATURE: true`, so the ecrecover check runs and the replayed signature passes because the hash is the same on both chains: [5](#0-4) 

The signature is then verified against the chain-ID-free hash in the Ethereum validation path: [6](#0-5) 

---

### Impact Explanation

An attacker who observes a valid unprotected legacy transaction on any EVM chain (Ethereum mainnet, testnets, other L2s) can submit the identical raw bytes to ZKsync OS. If the victim's nonce on ZKsync OS matches the nonce in the replayed transaction, the bootloader will:

1. Verify the signature successfully (same hash, same sig).
2. Increment the nonce.
3. Execute the transaction — transferring the victim's funds to the attacker-chosen recipient.

This is a direct, unauthorized movement of user funds with no privileged access required.

---

### Likelihood Explanation

- Unprotected legacy transactions (v=27/28) are still produced by older wallets, hardware signers, and scripts that predate EIP-155.
- The nonce-matching requirement is the primary constraint. It is satisfied trivially for nonce=0 (a user's very first transaction on any chain), which is the most common case for new ZKsync OS accounts.
- An attacker only needs to monitor public mempools or block explorers on any EVM chain for unprotected legacy transactions, then check whether the sender has a matching nonce and balance on ZKsync OS.
- No privileged access, leaked keys, or governance majority is required.

---

### Recommendation

Reject unprotected legacy transactions (v=27 or v=28) entirely at the parsing layer. ZKsync OS is a new chain and has no obligation to support pre-EIP-155 transactions. Add an explicit check:

```rust
if !legacy_signature.is_eip155() {
    return Err(InvalidTransaction::InvalidEncoding.into());
}
```

This should be inserted in `LegacyPayloadParser::try_parse_and_hash_for_signature_verification` before the hash branch, analogous to how all typed transactions (EIP-2930, EIP-1559, EIP-7702) enforce a chain-ID match. [7](#0-6) 

---

### Proof of Concept

**Setup:**
- Alice has 1 ETH on ZKsync OS (chain_id = 37) with nonce = 0.
- Alice previously sent an unprotected legacy transaction on Ethereum mainnet (chain_id = 1) with nonce = 0, v = 27, transferring 0.5 ETH to Bob.

**Attack:**
1. Attacker observes Alice's raw unprotected legacy transaction bytes on Ethereum mainnet.
2. Attacker submits the identical raw bytes to ZKsync OS.
3. `LegacyPayloadParser::try_parse_and_hash_for_signature_verification` computes `sig_hash = keccak256(rlp([0, gasPrice, gasLimit, Bob, 0.5 ETH, ""]))` — identical to the Ethereum mainnet hash.
4. `ecrecover(sig_hash, 27, r, s)` recovers Alice's address — the signature is valid.
5. Alice's nonce on ZKsync OS is 0, matching the transaction nonce — nonce check passes.
6. 0.5 ETH is transferred from Alice to Bob on ZKsync OS without Alice's authorization for this chain.

### Citations

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/legacy_tx.rs (L63-115)
```rust
impl LegacyPayloadParser {
    pub(crate) fn try_parse_and_hash_for_signature_verification<'a>(
        src: &'a [u8],
        expected_chain_id: u64,
    ) -> Result<(LegacyTXInner<'a>, LegacySignatureData<'a>, Bytes32), TxError> {
        // Legacy path: input must be a single list with 9 elements total.
        let mut outer = Rlp::new(src);

        // Strip the list encoding
        let mut inner = outer.list()?;

        // Outer list must be fully consumed
        if !outer.is_empty() {
            return Err(InvalidTransaction::InvalidStructure.into());
        }

        // Capture the concatenation bytes of the first 6 fields for hashing.
        let mark = inner.mark();
        let legacy_inner: LegacyTXInner<'a> = LegacyTXInner::decode_list_body(&mut inner)?;
        let inner_slice = inner.consumed_since(mark);

        let legacy_signature = LegacySignatureData::decode_list_body(&mut inner)?;
        if !inner.is_empty() {
            return Err(InvalidTransaction::InvalidStructure.into());
        }

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

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction.rs (L82-87)
```rust
    pub fn chain_id(&self) -> Option<u64> {
        match &self.inner {
            RlpEncodedTxInner::Legacy(_, _) => None,
            _ => Some(self.chain_id),
        }
    }
```

**File:** basic_bootloader/src/bootloader/config.rs (L10-15)
```rust
pub struct BasicBootloaderProvingExecutionConfig;

impl BasicBootloaderExecutionConfig for BasicBootloaderProvingExecutionConfig {
    const SIMULATION: bool = false;
    const VALIDATE_EOA_SIGNATURE: bool = true;
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L194-245)
```rust
    let suggested_signed_hash: Bytes32 = transaction.signed_hash()?;
    let from = *transaction.from();
    let Some((parity, r, s)) = transaction.sig_parity_r_s() else {
        // Ethereum txs should have signature
        return Err(InvalidTransaction::InvalidStructure.into());
    };

    if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
        // No native for Eth STF
    } else {
        if U256::from_be_slice(s) > U256::from_be_bytes(SECP256K1N_HALF) {
            return Err(InvalidTransaction::MalleableSignature.into());
        }

        let mut ecrecover_input = [0u8; 128];
        ecrecover_input[0..32].copy_from_slice(suggested_signed_hash.as_u8_array_ref());
        ecrecover_input[63] = (parity as u8) + 27;
        ecrecover_input[64..96][(32 - r.len())..].copy_from_slice(r);
        ecrecover_input[96..128][(32 - s.len())..].copy_from_slice(s);

        let mut ecrecover_output = ArrayBuilder::default();
        // We already charged gas for ecrecover in intrinsic cost, so we only need to charge native resources here.
        tx_resources
            .main_resources
            .with_infinite_ergs(|resources| {
                S::SystemFunctions::secp256k1_ec_recover(
                    ecrecover_input.as_slice(),
                    &mut ecrecover_output,
                    resources,
                    system.get_allocator(),
                )
                .map_err(SystemError::from)
            })?;

        if ecrecover_output.is_empty() {
            return Err(InvalidTransaction::IncorrectFrom {
                recovered: B160::ZERO,
                tx: from,
            }
            .into());
        }

        let recovered_from = B160::try_from_be_slice(&ecrecover_output.build()[12..])
            .ok_or(internal_error!("Invalid ecrecover return value"))?;

        if recovered_from != from {
            return Err(InvalidTransaction::IncorrectFrom {
                recovered: recovered_from,
                tx: from,
            }
            .into());
        }
```
