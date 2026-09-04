,
                data.len(),
                17
            );
            return None;
        }

        let stacked_ustx = parse_u128_from_be(data.get(0..16)?).unwrap();
        let num_cycles = *data.get(16)?;

        let mut signer_key: Option<StacksPublicKeyBuffer> = None;
        let mut max_amount: Option<u128> = None;
        let mut auth_id: Option<u32> = None;

        if data.len() >= 50 {
            signer_key = Some(StacksPublicKeyBuffer::from(data.get(17..50)?));
        }
        if data.len() >= 66 {
            let Some(amt) = parse_u128_from_be(data.get(50..66)?) else {
                return None;
            };
            max_amount = Some(amt);
        }
        if data.len() >= 70 {
            let Some(id) = parse_u32_from_be(data.get(66..70)?) else {
                return None;
            };
            auth_id = Some(id);
        }

        Some(ParsedData {
            stacked_ustx,
            num_cycles,
            signer_key,
            max_amount,
            auth_id,
        })
    }
```

**File:** stackslib/src/chainstate/burn/operations/stack_stx.rs (L232-247)
```rust
    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!(
