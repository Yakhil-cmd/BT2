### Title
Fee-on-Transfer NEP-141 Token Causes ERC-20 Over-Minting and Bridge Insolvency - (File: `engine/src/engine.rs`)

---

### Summary

When a NEP-141 token that charges a fee on every transfer is bridged into Aurora via `ft_on_transfer`, the engine mints ERC-20 tokens equal to the caller-supplied `args.amount` without verifying the actual NEP-141 balance increase. Because the fee-on-transfer token credits Aurora Engine with fewer tokens than `args.amount`, the ERC-20 supply for that token becomes permanently unbacked, causing insolvency and a permanent freeze of funds for the last withdrawers.

---

### Finding Description

The `ft_on_transfer` entrypoint in `engine/src/contract_methods/connector.rs` is called by a NEP-141 token contract after an `ft_transfer_call`. It reads `args.amount` directly from the JSON callback payload and passes it to `engine.receive_erc20_tokens`. [1](#0-0) 

`receive_erc20_tokens` in `engine/src/engine.rs` then calls `setup_receive_erc20_tokens_input` with `args.amount.as_u128()` to construct a `mint(recipient, amount)` call to the ERC-20 contract: [2](#0-1) 

The mint calldata is assembled as: [3](#0-2) 

The `EvmErc20.sol` `mint` function unconditionally mints the requested amount: [4](#0-3) 

**The root cause**: nowhere in this path does the engine verify that Aurora Engine's actual NEP-141 balance increased by `args.amount`. If the NEP-141 token charges a transfer fee (e.g., 1%), the NEP-141 contract credits Aurora Engine with `amount - fee` tokens but still calls `ft_on_transfer` with the original `amount`. Aurora Engine mints `amount` ERC-20 tokens while holding only `amount - fee` NEP-141 tokens, creating an unbacked surplus.

---

### Impact Explanation

**Insolvency / Permanent fund freeze.**

The total ERC-20 supply for the fee-on-transfer NEP-141 token exceeds the actual NEP-141 balance held by Aurora Engine. When users call `withdrawToNear` on `EvmErc20.sol`: [5](#0-4) 

The ERC-20 tokens are burned and a NEAR promise is issued to transfer NEP-141 tokens back. Once cumulative withdrawals exceed the actual NEP-141 balance held by Aurora Engine, the NEP-141 `ft_transfer` promise fails. The last depositors' ERC-20 tokens are permanently frozen — they are burned but the corresponding NEP-141 transfer reverts, destroying value with no recovery path.

An attacker who deposits fee-on-transfer NEP-141 tokens and immediately withdraws can drain the NEP-141 balance deposited by other users, since the attacker holds more ERC-20 tokens than the NEP-141 they contributed.

---

### Likelihood Explanation

Fee-on-transfer tokens exist in the NEAR ecosystem. Any such NEP-141 token that is registered via `deploy_erc20_token` and then bridged via `ft_transfer_call` triggers this path. The vulnerability requires no special privileges — any token holder can call `ft_transfer_call` on the NEP-141 contract. The `ft_on_transfer` entrypoint is a standard public NEAR contract method. [6](#0-5) 

---

### Recommendation

Before minting ERC-20 tokens, verify that the actual NEP-141 balance increase equals `args.amount`. Because NEAR cross-contract calls are asynchronous, the practical mitigations are:

1. **Whitelist approach**: Maintain an allowlist of NEP-141 tokens approved for bridging, explicitly excluding fee-on-transfer tokens. Reject `ft_on_transfer` calls from non-whitelisted NEP-141 accounts.
2. **Balance-check approach**: Issue a `ft_balance_of` view call to the NEP-141 contract before and after the transfer (using a callback pattern) and mint only the delta. This is complex in NEAR's async model but is the most robust fix.

---

### Proof of Concept

1. Deploy a fee-on-transfer NEP-141 token `fee_token.near` that deducts 10% on every `ft_transfer` / `ft_transfer_call`.
2. Call `deploy_erc20_token` on Aurora Engine to register `fee_token.near`, producing ERC-20 address `0xABC`.
3. **Victim**: Alice calls `ft_transfer_call("aurora", 1000, alice_evm_address)` on `fee_token.near`.
   - `fee_token.near` credits Aurora Engine with 900 tokens (10% fee taken).
   - `fee_token.near` calls `ft_on_transfer(alice, 1000, alice_evm_address)` on Aurora Engine.
   - Aurora Engine calls `mint(alice_evm_address, 1000)` on `0xABC`.
   - Alice holds 1000 ERC-20 tokens; Aurora Engine holds 900 NEP-141 tokens. **100 tokens are unbacked.**
4. **Attacker**: Bob repeats step 3 with 1000 tokens. Aurora Engine now holds 1800 NEP-141 tokens but has minted 2000 ERC-20 tokens.
5. Bob calls `withdrawToNear(bob_near, 1000)` on `0xABC`. ERC-20 burns 1000; NEP-141 transfers 1000 to Bob. Aurora Engine now holds 800 NEP-141 tokens.
6. Alice calls `withdrawToNear(alice_near, 1000)`. ERC-20 burns 1000; NEP-141 attempts to transfer 1000 — **fails** because Aurora Engine only holds 800. Alice's 1000 ERC-20 tokens are burned with no NEP-141 returned: **permanent fund freeze**. [7](#0-6) [8](#0-7)

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

**File:** engine/src/engine.rs (L796-839)
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
```

**File:** engine/src/engine.rs (L1305-1314)
```rust
#[must_use]
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
