### Title
Recipient Zero-Address Not Validated in `receive_base_tokens` Allows Permanent Freezing of Bridged ETH - (File: `engine/src/engine.rs`)

### Summary
The `receive_base_tokens` function, called during the `ft_on_transfer` bridge flow, parses the EVM recipient address from the user-controlled `msg` field without checking whether the resulting address is the zero address (`0x0000...0000`). An unprivileged NEAR user can supply the zero-address hex string as the `msg`, causing bridged ETH (base tokens) to be minted to `Address::zero()` and permanently frozen.

### Finding Description
When a user bridges ETH into Aurora via `ft_transfer_call`, the Aurora engine's `ft_on_transfer` entry point is invoked. If the predecessor is the ETH connector account, `receive_base_tokens` is called: [1](#0-0) 

Inside `receive_base_tokens`, the recipient is parsed from `args.msg` via `FtTransferMessageData::try_from`: [2](#0-1) 

The parser accepts any valid 40-character hex string, including `"0000000000000000000000000000000000000000"` (the zero address). No zero-address check is performed at any point in the parsing or in `receive_base_tokens` before calling `set_balance`: [3](#0-2) 

The `Address::zero()` constant is well-defined and accepted by all downstream code: [4](#0-3) 

The public NEAR contract entry point that triggers this path is: [5](#0-4) 

Which dispatches to: [6](#0-5) 

### Impact Explanation
Bridged ETH (base tokens) minted to `Address::zero()` are permanently inaccessible. There is no mechanism to recover funds from the zero address in the Aurora EVM. The total supply of bridged ETH on NEAR is not reduced (the NEP-141 tokens are consumed by Aurora), but the corresponding EVM balance is locked forever at the zero address. This constitutes **permanent freezing of funds**.

### Likelihood Explanation
The attack requires only a standard NEAR `ft_transfer_call` transaction directed at the Aurora contract with `msg = "0000000000000000000000000000000000000000"`. No special privileges, keys, or governance access are needed. Any NEAR account holding ETH on the connector can trigger this, including accidentally (e.g., a user who mistakenly passes an empty/zero address as the recipient). Likelihood is **High**.

### Recommendation
Add a zero-address guard in `receive_base_tokens` (and symmetrically in `receive_erc20_tokens`) immediately after parsing the recipient:

```rust
if receipient == Address::zero() {
    return Err(/* new error variant, e.g. */ errors::ERR_ZERO_ADDRESS_RECIPIENT);
}
```

Alternatively, add the check inside `FtTransferMessageData::try_from` so that all callers benefit from the validation centrally.

### Proof of Concept
1. A NEAR user holds ETH on the Aurora ETH connector (NEP-141 balance > 0).
2. The user calls `ft_transfer_call` on the ETH connector contract with:
   - `receiver_id`: Aurora engine contract account (e.g., `aurora`)
   - `amount`: any non-zero amount
   - `msg`: `"0000000000000000000000000000000000000000"` (40 hex chars = zero address)
3. The ETH connector calls `ft_on_transfer` on Aurora.
4. `ft_on_transfer` → `receive_base_tokens` is invoked.
5. `FtTransferMessageData::try_from("0000000000000000000000000000000000000000")` succeeds, returning `recipient = Address::zero()`.
6. `set_balance(&mut self.io, &Address::zero(), &new_balance)` is called — the bridged ETH is credited to the zero address.
7. The user's NEP-141 ETH balance is debited; the EVM balance at `0x0000...0000` is incremented. The funds are permanently frozen with no recovery path.

### Citations

**File:** engine/src/engine.rs (L773-790)
```rust
    pub fn receive_base_tokens(
        &mut self,
        args: &FtOnTransferArgs,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
        let amount = Wei::new_u128(args.amount.as_u128());
        let receipient = message_data.recipient;
        let balance = get_balance(&self.io, &receipient);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(errors::ERR_BALANCE_OVERFLOW)?;

        set_balance(&mut self.io, &receipient, &new_balance);

        sdk::log!("Mint {amount} base tokens for: {}", receipient.encode());

        Ok(None)
    }
```

**File:** engine-types/src/parameters/connector.rs (L40-57)
```rust
    fn try_from(message: &str) -> Result<Self, Self::Error> {
        if message.len() == 40 {
            // Parse message to determine recipient
            let recipient = {
                // Message format:
                // Recipient of the transaction - 40 characters (Address in hex)
                let mut address_bytes = [0; 20];
                hex::decode_to_slice(message, &mut address_bytes)
                    .map_err(|_| errors::ParseOnTransferMessageError::InvalidHexData)?;
                Address::from_array(address_bytes)
            };

            #[allow(deprecated)]
            return Ok(Self {
                recipient,
                fee: None,
            });
        }
```

**File:** engine-types/src/types/address.rs (L57-59)
```rust
    pub const fn zero() -> Self {
        Self::new(H160([0u8; 20]))
    }
```

**File:** engine/src/lib.rs (L602-609)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn ft_on_transfer() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::ft_on_transfer(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
```

**File:** engine/src/contract_methods/connector.rs (L62-108)
```rust
pub fn ft_on_transfer<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let current_account_id = env.current_account_id();
        let predecessor_account_id = env.predecessor_account_id();
        let mut engine: Engine<_, _> = Engine::new(
            predecessor_address(&predecessor_account_id),
            current_account_id.clone(),
            io,
            env,
        )?;

        sdk::log!("Call ft_on_transfer");

        let args: FtOnTransferArgs = read_json_args(&io)?;
        let result = if predecessor_account_id == get_connector_account_id(&io)? {
            engine.receive_base_tokens(&args)
        } else {
            engine.receive_erc20_tokens(
                &predecessor_account_id,
                &args,
                &current_account_id,
                handler,
            )
        };

        #[allow(clippy::used_underscore_binding)]
        let amount_to_return = if let Err(_err) = &result {
            sdk::log!("Error in ft_on_transfer: {_err:?}");
            // An error occurred, so we need to return the amount of tokens to the sender.
            args.amount.as_u128()
        } else {
            // Everything is ok, so return 0.
            0
        };

        let output = crate::prelude::format!("\"{amount_to_return}\"");
        io.return_output(output.as_bytes());

        // In case of an error, we just return Ok(None) to avoid a panic in the contract. It's ok
        // because in case of an error, we already returned the amount of tokens to the sender.
        Ok(result.unwrap_or(None))
    })
```
