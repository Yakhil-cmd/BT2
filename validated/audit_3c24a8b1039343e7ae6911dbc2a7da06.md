### Title
ERC-20 Mirror Over-Minting on Deflationary NEP-141 Deposit Leads to Insolvency - (File: `engine/src/engine.rs`)

---

### Summary

When a deflationary (fee-on-transfer) NEP-141 token is bridged into Aurora via `ft_transfer_call`, the NEP-141 contract deducts a transfer fee before calling `ft_on_transfer` on Aurora. Aurora's `receive_erc20_tokens` function mints ERC-20 tokens equal to `args.amount` — the **pre-fee stated amount** — rather than the actual tokens received. This inflates the ERC-20 total supply beyond Aurora's real NEP-141 holdings, creating a permanent insolvency: the last depositors to withdraw will find Aurora holds insufficient NEP-141 to honour their ERC-20 burn.

---

### Finding Description

The NEP-141 standard's `ft_transfer_call` flow works as follows:

1. Sender calls `ft_transfer_call(receiver_id: aurora, amount: N, msg: <evm_address>)` on the NEP-141 contract.
2. The NEP-141 contract transfers `N` tokens to Aurora. For a deflationary token, a fee `f` is deducted, so Aurora actually receives `N - f` tokens.
3. The NEP-141 contract then calls `ft_on_transfer(sender_id, amount: N, msg)` on Aurora — passing the **original** `N`, not the actual `N - f`.

Aurora's handler in `engine/src/contract_methods/connector.rs` reads `args.amount` and passes it directly to `receive_erc20_tokens`: [1](#0-0) 

Inside `receive_erc20_tokens`, the mint amount is taken verbatim from `args.amount`: [2](#0-1) 

`setup_receive_erc20_tokens_input` encodes a `mint(recipient, amount)` call to the ERC-20 contract using this inflated figure: [3](#0-2) 

The `EvmErc20.mint` function mints without any cross-check against actual NEP-141 balance: [4](#0-3) 

On withdrawal, `withdrawToNear` burns exactly the ERC-20 amount and calls the `ExitToNear` precompile, which issues an `ft_transfer` on the NEP-141 for the same amount: [5](#0-4) [6](#0-5) 

Because the ERC-20 total supply exceeds Aurora's actual NEP-141 balance, the NEP-141 `ft_transfer` calls will eventually fail for the last withdrawers.

---

### Impact Explanation

**Critical — Insolvency / Permanent Freezing of Funds.**

For every deposit of a deflationary NEP-141 token with fee rate `f`:
- Aurora mints `N` ERC-20 tokens but holds only `N - f` NEP-141 tokens.
- After `k` deposits of `N` each, ERC-20 supply = `k*N`, NEP-141 held = `k*(N-f)`.
- The deficit grows with each deposit.
- When users withdraw in order, the first withdrawers succeed (they drain the real NEP-141 balance), while the last withdrawers find Aurora's NEP-141 balance insufficient. Their ERC-20 tokens are permanently frozen — they burned ERC-20 but cannot receive NEP-141.

This exactly mirrors the original report's scenario: Alice (first depositor/withdrawer) loses proportionally more than Eve (last depositor/withdrawer) because the real NEP-141 pool is exhausted before all ERC-20 holders can redeem.

---

### Likelihood Explanation

**Medium-High.** Any unprivileged user can trigger this by:
1. Deploying or using an existing deflationary NEP-141 token that has been bridged to Aurora via `deploy_erc20_token`.
2. Calling `ft_transfer_call` on that NEP-141 with Aurora as receiver.

No admin access, governance capture, or special privilege is required. The NEP-141 standard explicitly allows fee-on-transfer tokens. The vulnerability is triggered by normal, intended bridge usage with a non-standard but valid token type.

---

### Recommendation

In `receive_erc20_tokens`, do not trust `args.amount` as the mint quantity. Instead, measure Aurora's actual NEP-141 balance before and after the `ft_on_transfer` callback (or use the NEP-141 contract's `ft_balance_of` view), and mint only the **net received** amount. Alternatively, document and enforce that only non-deflationary NEP-141 tokens may be bridged, and add an on-chain check or allowlist enforced at `deploy_erc20_token` time.

---

### Proof of Concept

**Setup:** Deploy a deflationary NEP-141 token `deflation.near` that charges a 1% fee on every `ft_transfer` / `ft_transfer_call`. Bridge it to Aurora via `deploy_erc20_token`.

**Steps:**

1. Alice calls `ft_transfer_call(aurora, 1000, alice_evm_addr)` on `deflation.near`.
   - `deflation.near` transfers 990 tokens to Aurora (1% fee), then calls `ft_on_transfer(alice, 1000, ...)`.
   - Aurora mints **1000** ERC-20 to Alice. Aurora holds **990** NEP-141.

2. Bob calls `ft_transfer_call(aurora, 1000, bob_evm_addr)`.
   - Aurora receives 990 NEP-141, mints **1000** ERC-20 to Bob. Aurora holds **1980** NEP-141.

3. Eve calls `ft_transfer_call(aurora, 1000, eve_evm_addr)`.
   - Aurora receives 990 NEP-141, mints **1000** ERC-20 to Eve. Aurora holds **2970** NEP-141.
   - **ERC-20 total supply = 3000; NEP-141 held = 2970. Deficit = 30.**

4. Alice calls `withdrawToNear(alice_near, 1000)` on the ERC-20.
   - Burns 1000 ERC-20. Aurora calls `ft_transfer(alice_near, 1000)` on `deflation.near`. Aurora now holds **1970** NEP-141.

5. Bob calls `withdrawToNear(bob_near, 1000)`.
   - Burns 1000 ERC-20. Aurora calls `ft_transfer(bob_near, 1000)`. Aurora now holds **970** NEP-141.

6. Eve calls `withdrawToNear(eve_near, 1000)`.
   - Burns 1000 ERC-20. Aurora calls `ft_transfer(eve_near, 1000)` — **FAILS**: Aurora only holds 970 NEP-141.
   - Eve's 1000 ERC-20 are burned but she receives nothing. Her funds are **permanently frozen**.

The root cause is at: [7](#0-6) 

where `args.amount` (the pre-fee stated amount) is used as the mint quantity instead of the actual tokens received by Aurora.

### Citations

**File:** engine/src/contract_methods/connector.rs (L80-99)
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
```

**File:** engine/src/engine.rs (L803-839)
```rust
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
