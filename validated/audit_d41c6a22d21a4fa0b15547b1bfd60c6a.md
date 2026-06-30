### Title
`ExitToEthereum` Precompile Accepts `address(0)` as Recipient, Permanently Burning Bridged Funds - (File: engine-precompiles/src/native.rs)

### Summary
The `ExitToEthereum` precompile (`0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`) does not validate that the caller-supplied `recipient_address` is non-zero. Any EVM user can invoke it with 20 zero bytes as the Ethereum recipient, causing their ETH (flag `0x00`) or ERC-20 tokens (flag `0x01`) to be permanently destroyed: the Aurora-side balance is debited and a NEAR `withdraw` promise is dispatched to the eth-connector targeting `0x0000000000000000000000000000000000000000`, with no recovery path.

### Finding Description
In `ExitToEthereum::run()`, after stripping the flag byte, the 20-byte Ethereum recipient is parsed with no zero-address guard:

```rust
// flag 0x0 path – ETH base token exit
let recipient_address: Address = input
    .try_into()
    .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")))?;
// … no check that recipient_address != Address::zero() …
serialize_fn(recipient_address, context.apparent_value)?
```

`Address::try_from_slice` succeeds for 20 zero bytes, returning `Address::zero()`. The precompile then serialises this zero address into the `withdraw` call-args and emits a NEAR promise log. The EVM runtime has already debited `context.apparent_value` from the caller's balance before the precompile runs.

The identical gap exists in the ERC-20 path (flag `0x01`): `recipient_address` is parsed from the trailing 20 bytes with `Address::try_from_slice` and is never checked for zero.

The `receive_base_tokens` function in `engine/src/engine.rs` has the same structural gap: `FtTransferMessageData::try_from` successfully parses a 40-hex-zero message string into `recipient = Address::zero()`, and `set_balance` credits that zero address with the bridged amount, permanently locking it.

### Impact Explanation
- **Aurora side**: the caller's ETH balance is reduced by the full `apparent_value`; the reduction is committed before the NEAR promise is scheduled.
- **Ethereum side**: the eth-connector receives a `withdraw` call with `recipient = 0x0000000000000000000000000000000000000000`. Whether the custodian contract on Ethereum accepts or rejects this determines whether the ETH is also burned there; either way the Aurora-side funds are gone.
- Without the `error_refund` feature flag active, there is no callback path that can return the funds to the caller.
- Result: **permanent, irreversible destruction of user funds** — matching "Critical: Permanent freezing of funds."

### Likelihood Explanation
The precompile is reachable by any unprivileged EVM account or contract. Realistic trigger paths include:
1. A Solidity contract that passes an uninitialised `address` variable as the Ethereum recipient.
2. A user who mistakenly supplies the zero address (e.g., copy-paste error, default value).
3. A malicious contract that deliberately routes a victim's ETH through a wrapper that hard-codes `address(0)` as the destination.

No special privilege, governance action, or admin key is required.

### Recommendation
Add an explicit zero-address guard immediately after parsing `recipient_address` in both the ETH base-token path and the ERC-20 path of `ExitToEthereum::run()`:

```rust
if recipient_address == Address::zero() {
    return Err(ExitError::Other(Cow::from("ERR_RECIPIENT_IS_ZERO_ADDRESS")));
}
```

Apply the same guard in `receive_base_tokens` after resolving `message_data.recipient`.

### Proof of Concept
1. From any Aurora EVM account, call the `ExitToEthereum` precompile at `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab` with:
   - `value = N wei` (any non-zero amount)
   - `calldata = 0x00` + `0x0000000000000000000000000000000000000000` (flag byte `0x00` followed by 20 zero bytes)
2. `ExitToEthereum::run()` parses `recipient_address = Address::zero()` — no error is returned.
3. The precompile emits a NEAR promise log encoding a `withdraw` call to the eth-connector with `recipient = "0000000000000000000000000000000000000000"` and `amount = N`.
4. The EVM debits `N wei` from the caller's Aurora balance.
5. The NEAR promise executes; the ETH is directed to `address(0)` on Ethereum.
6. The caller's `N wei` is permanently unrecoverable.

**Root cause location:** [1](#0-0) 

**ERC-20 path (same gap):** [2](#0-1) 

**`receive_base_tokens` parallel gap:** [3](#0-2)

### Citations

**File:** engine-precompiles/src/native.rs (L894-896)
```rust
                let recipient_address: Address = input
                    .try_into()
                    .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")))?;
```

**File:** engine-precompiles/src/native.rs (L946-947)
```rust
                    let recipient_address = Address::try_from_slice(input)
                        .map_err(|_| ExitError::Other(Cow::from("ERR_WRONG_ADDRESS")))?;
```

**File:** engine/src/engine.rs (L777-785)
```rust
        let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
        let amount = Wei::new_u128(args.amount.as_u128());
        let receipient = message_data.recipient;
        let balance = get_balance(&self.io, &receipient);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(errors::ERR_BALANCE_OVERFLOW)?;

        set_balance(&mut self.io, &receipient, &new_balance);
```
