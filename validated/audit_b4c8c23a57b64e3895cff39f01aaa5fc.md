### Title
Unverified NEP-141 Token Transfer in `ft_on_transfer` Allows Minting Unbacked ERC-20 Tokens - (File: `engine/src/contract_methods/connector.rs`)

---

### Summary

The `ft_on_transfer` public NEAR method in Aurora Engine mints ERC-20 tokens based solely on the caller's `predecessor_account_id` and the `amount` field in the JSON arguments, without any on-chain verification that the corresponding NEP-141 tokens were actually transferred to Aurora. Any NEAR account that controls a registered NEP-141 token can call `ft_on_transfer` directly — bypassing the `ft_transfer_call` flow entirely — to mint arbitrary amounts of the corresponding ERC-20 token on Aurora with zero NEP-141 backing, breaking the 1:1 invariant and causing insolvency for legitimate ERC-20 holders.

---

### Finding Description

`ft_on_transfer` is a public NEAR contract method. In the intended NEP-141 bridge flow, a user calls `ft_transfer_call` on the NEP-141 contract, which atomically transfers tokens to Aurora and then calls `ft_on_transfer` on Aurora as a callback. Aurora trusts this callback to reflect a real transfer.

The critical logic in `ft_on_transfer` is:

```rust
let result = if predecessor_account_id == get_connector_account_id(&io)? {
    engine.receive_base_tokens(&args)   // ETH path: protected by connector account check
} else {
    engine.receive_erc20_tokens(        // ERC-20 path: NO equivalent protection
        &predecessor_account_id,
        &args,
        &current_account_id,
        handler,
    )
};
``` [1](#0-0) 

For the base-ETH path, `receive_base_tokens` is gated by `predecessor_account_id == get_connector_account_id(&io)?` — only the configured ETH connector account can mint ETH. No analogous guard exists for the ERC-20 path.

In `receive_erc20_tokens`, the engine simply looks up the ERC-20 address for the calling account and mints tokens:

```rust
let erc20_token = get_erc20_from_nep141(&self.io, token)?;
let erc20_admin_address = current_address(current_account_id);
let result = self.call(
    &erc20_admin_address,
    &erc20_token,
    Wei::zero(),
    setup_receive_erc20_tokens_input(&recipient, amount),
    ...
).and_then(submit_result_or_err)?;
``` [2](#0-1) 

There is no check that Aurora's NEP-141 balance actually increased by `amount` before the mint. The function trusts the caller-supplied `amount` field in `FtOnTransferArgs` unconditionally. [3](#0-2) 

`deploy_erc20_token` is permissionless — any NEAR account can register a NEP-141 → ERC-20 mapping: [4](#0-3) 

---

### Impact Explanation

**Critical — Insolvency / Direct theft of user funds.**

An attacker who controls a NEAR account registered as a NEP-141 token in Aurora can:

1. Mint arbitrary ERC-20 tokens on Aurora with zero NEP-141 backing.
2. Sell those unbacked ERC-20 tokens to other users on Aurora DEXes.
3. When legitimate holders attempt to exit (burn ERC-20 → receive NEP-141 via `withdrawToNear`), Aurora's NEP-141 balance is insufficient to cover all exits.
4. Legitimate users' ERC-20 tokens become permanently worthless — their funds are stolen.

The `set_balance` / ERC-20 `mint` call updates Aurora's internal accounting without any corresponding real asset: [5](#0-4) 

---

### Likelihood Explanation

**Medium.** The attacker must:
1. Deploy any NEP-141 token contract at a NEAR account they control (permissionless).
2. Call `deploy_erc20_token` on Aurora to register the NEP-141 → ERC-20 mapping (permissionless).
3. Call `ft_on_transfer` directly on Aurora from their NEP-141 account with an arbitrary `amount`.

No admin access, governance capture, or key compromise is required. The entire setup is permissionless and reachable by any unprivileged NEAR account.

---

### Recommendation

1. **Balance-delta verification**: Before minting ERC-20 tokens, record Aurora's NEP-141 balance, then verify it increased by at least `amount` after the transfer. This requires a cross-contract view call, which can be structured as a promise-with-callback pattern similar to how `deploy_erc20_token_callback` already works.

2. **Restrict `ft_on_transfer` to the `ft_transfer_call` context**: NEAR's `ft_transfer_call` standard guarantees the NEP-141 contract calls `ft_on_transfer` only after a successful transfer. Aurora could enforce this by requiring the call to arrive as a promise callback (checking `env.assert_private_call()` or verifying promise result data), rather than accepting direct calls.

3. **Asymmetry fix**: Apply the same trust model to ERC-20 minting that already protects base-ETH minting — i.e., only allow `ft_on_transfer` to mint ERC-20 tokens when called as a callback from a verified `ft_transfer_call` receipt, not as a direct top-level call.

---

### Proof of Concept

```
1. Attacker deploys a NEP-141 token contract at `evil-token.near`.

2. Attacker calls `deploy_erc20_token` on Aurora with `nep141 = "evil-token.near"`.
   → Aurora registers evil-token.near → ERC-20 address mapping.

3. Attacker calls `ft_on_transfer` on Aurora directly from `evil-token.near`:
   {
     "sender_id": "evil-token.near",
     "amount": "1000000000000000000000000",
     "msg": "<attacker_evm_address_hex>"
   }
   predecessor_account_id = "evil-token.near"

4. Aurora executes:
   - get_erc20_from_nep141("evil-token.near") → returns ERC-20 address ✓
   - Calls ERC-20.mint(attacker_evm_address, 1000000000000000000000000)
   - No NEP-141 tokens were ever transferred to Aurora.

5. Attacker sells 1,000,000 ERC-20 tokens to users on Aurora DEXes.

6. Users attempt to exit via `withdrawToNear` (burn ERC-20 → receive NEP-141).
   Aurora holds 0 NEP-141 tokens → exits fail → user funds permanently frozen.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** engine/src/contract_methods/connector.rs (L62-109)
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
}
```

**File:** engine/src/contract_methods/connector.rs (L111-131)
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
            }
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

**File:** engine/src/engine.rs (L1523-1528)
```rust
pub fn set_balance<I: IO>(io: &mut I, address: &Address, balance: &Wei) {
    io.write_storage(
        &address_to_key(KeyPrefix::Balance, address),
        &balance.to_bytes(),
    );
}
```

**File:** engine-types/src/parameters/connector.rs (L193-199)
```rust
/// Parameters for the `ft_on_transfer` transaction for regular NEP-141 tokens.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Deserialize, Serialize, PartialEq, Eq)]
pub struct FtOnTransferArgs {
    pub sender_id: AccountId,
    pub amount: Balance,
    pub msg: String,
}
```
