### Title
Fee-on-Transfer NEP-141 Token Causes ERC-20 Mirror Over-Minting and Bridge Insolvency - (File: engine/src/engine.rs)

### Summary
The `receive_erc20_tokens` function in `engine/src/engine.rs` unconditionally trusts the `amount` field reported in the `ft_on_transfer` callback to mint ERC-20 mirror tokens. If a bridged NEP-141 token implements a fee-on-transfer mechanism, Aurora receives fewer tokens than `args.amount` but mints the full `args.amount` in ERC-20 tokens. This creates an under-collateralized ERC-20 mirror, leading to bridge insolvency: the last users to exit cannot withdraw their NEP-141 tokens, and those NEP-141 tokens become permanently frozen inside Aurora.

### Finding Description

The NEP-141 ↔ ERC-20 bridge flow works as follows:

1. A user calls `ft_transfer_call(amount, msg, receiver=aurora)` on a NEP-141 contract.
2. The NEP-141 contract transfers tokens to Aurora and calls `ft_on_transfer` on Aurora with `amount`.
3. Aurora's `ft_on_transfer` entrypoint (in `engine/src/contract_methods/connector.rs`) dispatches to `engine.receive_erc20_tokens(...)`.
4. `receive_erc20_tokens` reads `let amount = args.amount.as_u128()` and immediately uses that value to mint ERC-20 tokens via `setup_receive_erc20_tokens_input(&recipient, amount)`.

The critical flaw is at step 4: the engine mints exactly `args.amount` ERC-20 tokens without ever verifying how many NEP-141 tokens Aurora's account actually received. The NEP-141 standard does not prohibit fee-on-transfer implementations. A non-standard NEP-141 token can deduct a fee during `ft_transfer_call` (so Aurora receives `amount - fee`) while still invoking `ft_on_transfer` with the original `amount`. Aurora then mints `amount` ERC-20 tokens backed by only `amount - fee` NEP-141 tokens.

There is no whitelist restricting which NEP-141 tokens can be deployed as ERC-20 mirrors. `deploy_erc20_token` is a public NEAR contract method callable by any account.

**Relevant code path:**

`engine/src/contract_methods/connector.rs` `ft_on_transfer` → `engine.receive_erc20_tokens`: [1](#0-0) 

`engine/src/engine.rs` `receive_erc20_tokens` — amount is taken directly from callback args and used to mint: [2](#0-1) 

`engine/src/engine.rs` `setup_receive_erc20_tokens_input` — mints exactly `amount` ERC-20 tokens: [3](#0-2) 

`etc/eth-contracts/contracts/EvmErc20.sol` `mint` — called by the admin (Aurora engine address) to credit the recipient: [4](#0-3) 

On exit, `withdrawToNear` burns the ERC-20 and calls the `ExitToNear` precompile, which schedules an `ft_transfer` promise for the full burned amount: [5](#0-4) [6](#0-5) 

Because Aurora holds fewer NEP-141 tokens than the total ERC-20 supply, the `ft_transfer` promise for the last exiting user will fail.

### Impact Explanation

**Critical — Insolvency / Permanent Fund Freeze.**

- Aurora mints `N` ERC-20 tokens but holds only `N - fee` NEP-141 tokens as backing.
- The ERC-20 mirror is permanently under-collateralized by `fee` tokens per bridge deposit.
- With multiple depositors, the deficit accumulates. The last users to call `withdrawToNear` will have their `ft_transfer` promise fail.
- **Without `error_refund` feature**: the ERC-20 tokens are burned but no NEP-141 is returned — permanent loss of both the ERC-20 and the NEP-141 backing.
- **With `error_refund` feature**: the ERC-20 tokens are refunded, but the `fee` worth of NEP-141 tokens held by Aurora can never be withdrawn by anyone — permanent freeze of those NEP-141 tokens inside Aurora.

### Likelihood Explanation

- Any account can deploy a fee-on-transfer NEP-141 token on NEAR (no special privileges required).
- Any account can call `deploy_erc20_token` on Aurora to register an ERC-20 mirror for that token (no whitelist).
- Any account can then call `ft_transfer_call` to bridge tokens, triggering the accounting discrepancy.
- The entire attack path is unprivileged and externally reachable.

### Recommendation

In `receive_erc20_tokens`, do not trust `args.amount` as the canonical minted amount. Instead, record Aurora's NEP-141 balance for the token before and after the `ft_transfer_call` completes (using a balance-check callback pattern), and mint only the difference. Alternatively, maintain an explicit per-token NEP-141 reserve ledger and reconcile it on each deposit, rejecting or adjusting for any shortfall.

### Proof of Concept

1. Deploy a NEAR contract implementing NEP-141 with a 10% fee-on-transfer: when `ft_transfer_call(1000, ...)` is called, it transfers only 900 tokens to Aurora but calls `ft_on_transfer` with `amount = 1000`.
2. Call `deploy_erc20_token` on Aurora to register an ERC-20 mirror for this NEP-141.
3. Call `ft_transfer_call(1000, hex(recipient_address))` on the fee token → Aurora receives 900 NEP-141 but mints 1000 ERC-20 to `recipient_address`.
4. Repeat with a second user depositing 1000 → Aurora now holds 1800 NEP-141 but has 2000 ERC-20 in circulation.
5. First user calls `withdrawToNear(1000)` → ERC-20 burned, `ft_transfer(1000)` succeeds (Aurora has 1800 ≥ 1000). Aurora now holds 800 NEP-141.
6. Second user calls `withdrawToNear(1000)` → ERC-20 burned, `ft_transfer(1000)` fails (Aurora only has 800). Second user's funds are frozen.

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

**File:** engine/src/engine.rs (L1306-1314)
```rust
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),
    ]);

    [selector, tail.as_slice()].concat()
}
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L49-51)
```text
    function mint(address account, uint256 amount) public onlyAdmin {
        _mint(account, amount);
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

**File:** engine-precompiles/src/native.rs (L627-646)
```rust
        _ => {
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
                None,
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
```
