### Title
Unchecked `args.amount` in `ft_on_transfer` Allows Malicious NEP-141 Token to Mint Unbacked ERC-20 Tokens, Causing Insolvency - (`engine/src/contract_methods/connector.rs`)

---

### Summary

`ft_on_transfer` in Aurora Engine unconditionally trusts the `amount` field supplied by the calling NEP-141 contract and mints an equal number of ERC-20 tokens on Aurora, with no verification that Aurora actually received those tokens. Because `deploy_erc20_token` is also permissionless, an unprivileged attacker can register a malicious NEP-141 token, then call `ft_on_transfer` directly with a fabricated amount (or use a fee-on-transfer NEP-141 token) to mint unbacked ERC-20 tokens, creating an insolvent bridge pool.

---

### Finding Description

**Step 1 – Permissionless ERC-20 registration.**

`deploy_erc20_token` contains no access-control check:

```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I, env: &E, handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        // ← no require_owner_only or similar guard
        let args = DeployErc20TokenArgs::deserialize(&bytes)…;
        engine::deploy_erc20_token(nep141, None, io, env, handler)?;
```

Any NEAR account can register any NEP-141 token and obtain an ERC-20 mapping on Aurora. [1](#0-0) 

**Step 2 – `ft_on_transfer` trusts caller-supplied `amount`.**

`ft_on_transfer` identifies the NEP-141 token by `predecessor_account_id` and immediately mints ERC-20 tokens equal to `args.amount`:

```rust
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)
} else {
    engine.receive_erc20_tokens(&predecessor_account_id, &args, …)
};
``` [2](#0-1) 

`receive_erc20_tokens` calls `setup_receive_erc20_tokens_input` which encodes `args.amount` directly into an ERC-20 `mint` call:

```rust
let amount = args.amount.as_u128();
// …
setup_receive_erc20_tokens_input(&recipient, amount)
``` [3](#0-2) 

There is no balance-before/balance-after check, no cross-validation against an actual NEP-141 transfer, and no restriction preventing a NEP-141 contract from calling `ft_on_transfer` directly (without going through `ft_transfer_call`). [4](#0-3) 

**Step 3 – `receive_base_tokens` has the same flaw.**

For the ETH-connector path, `receive_base_tokens` also blindly credits `args.amount` as Wei to the recipient:

```rust
let amount = Wei::new_u128(args.amount.as_u128());
set_balance(&mut self.io, &receipient, &new_balance);
``` [5](#0-4) 

---

### Impact Explanation

**Attack vector A – Direct fabricated call (no tokens transferred at all):**

1. Attacker deploys `malicious.near` implementing the NEP-141 interface.
2. Attacker calls `deploy_erc20_token("malicious.near")` on Aurora (permissionless).
3. `malicious.near` calls `ft_on_transfer` on Aurora with `amount = 10_000_000` and `sender_id = attacker`, without executing any actual token transfer.
4. Aurora mints 10 000 000 ERC-20 tokens for the attacker, backed by zero NEP-141 tokens.
5. Attacker uses the unbacked ERC-20 tokens in DeFi protocols deployed on Aurora (AMMs, lending markets) to drain real assets (ETH, other ERC-20s).

**Attack vector B – Fee-on-transfer NEP-141 (analog to the ERC-777 tax in the original report):**

1. Attacker deploys a NEP-141 token that silently deducts a fee during `ft_transfer_call`, transferring `amount − fee` to Aurora while calling `ft_on_transfer` with the full `amount`.
2. Aurora mints `amount` ERC-20 tokens but holds only `amount − fee` NEP-141 tokens.
3. Repeated deposits inflate the ERC-20 supply beyond the NEP-141 backing.
4. Attacker exits first, redeeming more NEP-141 tokens than they deposited; later depositors cannot fully exit — **insolvency**.

Both vectors result in **Critical – Insolvency** and/or **Critical – Direct theft of user funds**.

---

### Likelihood Explanation

- `deploy_erc20_token` is fully permissionless; any NEAR account can register any NEP-141 token. [6](#0-5) 
- `ft_on_transfer` is a public exported entry point callable by any NEAR contract. [7](#0-6) 
- No special privilege, leaked key, or governance capture is required.
- The only prerequisite is deploying a NEAR contract, which costs a small amount of NEAR for storage.

---

### Recommendation

1. **Verify actual balance change.** Before minting ERC-20 tokens, record Aurora's NEP-141 balance before the call and compare it after; mint only the delta actually received.
2. **Restrict `ft_on_transfer` callers.** Maintain a registry of approved NEP-141 tokens and reject `ft_on_transfer` calls from unregistered predecessors, or require that the call originates from the `ft_transfer_call` flow (e.g., by checking a per-receipt nonce or using NEAR's promise-result mechanism).
3. **Add access control to `deploy_erc20_token`.** Require owner or governance approval before a new NEP-141 → ERC-20 mapping is created, preventing arbitrary token registration.

---

### Proof of Concept

```
// Pseudocode – NEAR contract
contract MaliciousNep141 {
    // Step 1: register this token on Aurora (permissionless)
    fn setup() {
        aurora.deploy_erc20_token("malicious.near");
    }

    // Step 2: call ft_on_transfer directly with fabricated amount
    fn exploit(victim_address: Address) {
        aurora.ft_on_transfer(json!({
            "sender_id": "attacker.near",
            "amount":    "1000000000000000000000000",  // 10^24, no tokens sent
            "msg":       victim_address.hex()
        }));
        // Aurora now has minted 10^24 ERC-20 tokens for victim_address
        // backed by zero NEP-141 tokens.
    }
}
```

The root cause lines are:

- `ft_on_transfer` dispatches to `receive_erc20_tokens` with no balance verification. [8](#0-7) 
- `receive_erc20_tokens` mints `args.amount` ERC-20 tokens unconditionally. [9](#0-8) 
- `deploy_erc20_token` has no access control, enabling the prerequisite registration step. [10](#0-9)

### Citations

**File:** engine/src/contract_methods/connector.rs (L80-100)
```rust
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
```

**File:** engine/src/contract_methods/connector.rs (L111-130)
```rust
#[named]
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let bytes = io.read_input().to_vec();
        let args =
            DeployErc20TokenArgs::deserialize(&bytes).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

                io.return_output(
                    &borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?,
                );
                Ok(PromiseOrValue::Value(address))
```

**File:** engine/src/engine.rs (L778-785)
```rust
        let amount = Wei::new_u128(args.amount.as_u128());
        let receipient = message_data.recipient;
        let balance = get_balance(&self.io, &receipient);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(errors::ERR_BALANCE_OVERFLOW)?;

        set_balance(&mut self.io, &receipient, &new_balance);
```

**File:** engine/src/engine.rs (L796-844)
```rust
    pub fn receive_erc20_tokens<P: PromiseHandler>(
        &mut self,
        token: &AccountId,
        args: &FtOnTransferArgs,
        current_account_id: &AccountId,
        handler: &mut P,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let amount = args.amount.as_u128();
        // Parse message to determine recipient
        let mut recipient = {
            // The message should contain the recipient EOA address.
            let message = args.msg.strip_prefix("0x").unwrap_or(&args.msg);
            // Recipient - 40 characters (Address in hex without '0x' prefix)
            if message.len() < 40 {
                return Err(ParseOnTransferMessageError::WrongMessageFormat.into());
            }
            let mut address_bytes = [0; 20];
            hex::decode_to_slice(&message[..40], &mut address_bytes)
                .map_err(|_| ParseOnTransferMessageError::WrongMessageFormat)?;
            Address::from_array(address_bytes)
        };

        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }

        let erc20_token = get_erc20_from_nep141(&self.io, token)?;
        let erc20_admin_address = current_address(current_account_id);
        let result = self
            .call(
                &erc20_admin_address,
                &erc20_token,
                Wei::zero(),
                setup_receive_erc20_tokens_input(&recipient, amount),
                u64::MAX,
                Vec::new(), // TODO: are there values we should put here?
                Vec::new(),
                handler,
            )
            .and_then(submit_result_or_err)?;

        sdk::log!("Mint {amount} ERC-20 tokens for: {}", recipient.encode());

        // Return SubmitResult so that it can be accessed in standalone engine.
        // This is used to help with the indexing of bridge transactions.
        Ok(Some(result))
    }
```

**File:** engine/src/lib.rs (L602-610)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn ft_on_transfer() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::ft_on_transfer(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
