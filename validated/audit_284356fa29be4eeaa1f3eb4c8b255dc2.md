### Title
Deflationary NEP-141 Token Deposit Mints Excess ERC-20 Tokens, Causing Bridge Insolvency — (File: `engine/src/engine.rs`)

---

### Summary

`receive_erc20_tokens` in `engine/src/engine.rs` mints ERC-20 tokens using the caller-supplied `args.amount` from the `ft_on_transfer` callback without verifying Aurora's actual NEP-141 balance change. A deflationary (burn-on-transfer) NEP-141 token causes Aurora to mint more ERC-20 tokens than the NEP-141 tokens it actually holds, making the bridge insolvent for that token.

---

### Finding Description

When a NEP-141 token is bridged into Aurora via `ft_transfer_call`, the NEP-141 contract calls `ft_on_transfer` on Aurora. Aurora's handler dispatches to `receive_erc20_tokens`: [1](#0-0) 

Inside `receive_erc20_tokens`, the mint amount is taken verbatim from `args.amount`: [2](#0-1) 

`setup_receive_erc20_tokens_input` encodes a `mint(recipient, amount)` call to the ERC-20 contract: [3](#0-2) 

The `amount` field in `FtOnTransferArgs` is the amount the NEP-141 contract *claims* to have transferred: [4](#0-3) 

A deflationary NEP-141 token burns a portion of tokens during transfer. Its `ft_transfer_call` implementation deducts `amount` from the sender, burns a fee, credits only `amount - fee` to Aurora's balance, then calls `ft_on_transfer(sender, amount, msg)` with the original `amount`. Aurora never queries its actual NEP-141 balance before and after the transfer; it blindly mints the full stated `amount` of ERC-20 tokens.

Any user can register a new NEP-141 token on Aurora via `deploy_erc20_token`, which has no access control: [5](#0-4) 

---

### Impact Explanation

After each deflationary deposit, Aurora's ERC-20 supply for that token exceeds the NEP-141 tokens it actually holds. When users attempt to exit via `withdrawToNear` / `withdrawToEthereum` (which burns ERC-20 tokens and calls `ft_transfer` on the NEP-141 contract), Aurora will eventually be unable to fulfill withdrawals because it holds fewer NEP-141 tokens than the outstanding ERC-20 supply.

- **Without `error_refund` feature** (`EvmErc20.sol`): ERC-20 tokens are burned first, then the NEP-141 `ft_transfer` fails. The ERC-20 tokens are permanently destroyed with no NEP-141 received — **permanent fund freeze**. [6](#0-5) 

- **With `error_refund` feature** (`EvmErc20V2.sol`): The callback refunds ERC-20 tokens on failure, but the bridge remains insolvent — users are stuck in a loop unable to exit — **insolvency / temporary freeze**. [7](#0-6) 

---

### Likelihood Explanation

- Any unprivileged NEAR account can deploy a deflationary NEP-141 token and register it on Aurora via `deploy_erc20_token` (no admin check).
- The attacker then calls `ft_transfer_call` on the deflationary NEP-141 contract targeting Aurora.
- No privileged access, no leaked keys, no governance capture required.
- The discrepancy accumulates with every deposit, making the insolvency grow monotonically.

---

### Recommendation

In `receive_erc20_tokens`, do not trust `args.amount` as the mint quantity. Instead, query Aurora's actual NEP-141 balance on the token contract before and after the transfer (via a cross-contract view call or by relying on the resolved amount from `ft_resolve_transfer`), and mint only the delta actually received. This mirrors the standard "balance-before / balance-after" pattern recommended for deflationary token support.

---

### Proof of Concept

1. Deploy a deflationary NEP-141 token `deflation.near` that burns 10% on every transfer.
2. Call `deploy_erc20_token` on Aurora with `deflation.near` — succeeds with no access check.
3. Call `ft_transfer_call(aurora, 1000, "<recipient_evm_address>")` on `deflation.near`.
4. `deflation.near` burns 100 tokens, credits 900 to Aurora's NEP-141 balance, then calls `ft_on_transfer(sender, 1000, msg)` on Aurora.
5. Aurora's `receive_erc20_tokens` reads `args.amount = 1000` and mints 1000 ERC-20 tokens to the recipient.
6. Aurora now holds 900 NEP-141 tokens but has 1000 ERC-20 tokens outstanding — 100-token deficit.
7. Repeat step 3 N times; the deficit grows by 100 per iteration.
8. When any holder calls `withdrawToNear(recipient, 1000)` on the ERC-20 contract, 1000 ERC-20 tokens are burned, Aurora attempts `ft_transfer(recipient, 1000)` on `deflation.near`, but Aurora's balance is insufficient — the transfer fails.
9. Without `error_refund`: the 1000 ERC-20 tokens are permanently destroyed, the user receives nothing — permanent fund freeze. [8](#0-7)

### Citations

**File:** engine/src/contract_methods/connector.rs (L80-90)
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
```

**File:** engine/src/contract_methods/connector.rs (L112-130)
```rust
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

**File:** engine/src/engine.rs (L1306-1313)
```rust
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),
    ]);

    [selector, tail.as_slice()].concat()
```

**File:** engine-types/src/parameters/connector.rs (L194-199)
```rust
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Deserialize, Serialize, PartialEq, Eq)]
pub struct FtOnTransferArgs {
    pub sender_id: AccountId,
    pub amount: Balance,
    pub msg: String,
}
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-64)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```
