### Title
Incorrect Accounting on Fee-on-Transfer NEP-141 Tokens in `ft_on_transfer` / `receive_erc20_tokens` — (`engine/src/engine.rs`)

### Summary
`receive_erc20_tokens` unconditionally mints ERC-20 tokens equal to `args.amount` — the value supplied by the calling NEP-141 contract — without verifying the amount Aurora actually received. For a fee-on-transfer or deflationary NEP-141 token, the actual balance credited to Aurora is less than `args.amount`, so Aurora mints more ERC-20 tokens than it holds NEP-141 backing. Any user can later redeem those inflated ERC-20 tokens, draining NEP-141 tokens that belong to other depositors.

### Finding Description

The NEAR NEP-141 `ft_transfer_call` standard works as follows:
1. Caller invokes `ft_transfer_call(receiver_id=aurora, amount=X, msg=<evm_address>)` on the NEP-141 contract.
2. The NEP-141 contract transfers tokens to Aurora and calls `ft_on_transfer` on Aurora with `amount=X`.
3. Aurora's `ft_on_transfer` dispatches to `receive_erc20_tokens`.

Inside `receive_erc20_tokens`:

```rust
// engine/src/engine.rs  line 803
let amount = args.amount.as_u128();   // ← taken verbatim from the NEP-141 contract's call
``` [1](#0-0) 

This `amount` is then passed directly to `setup_receive_erc20_tokens_input`, which encodes a `mint(recipient, amount)` call to the ERC-20 mirror contract:

```rust
// engine/src/engine.rs  lines 826-837
setup_receive_erc20_tokens_input(&recipient, amount)
``` [2](#0-1) 

```rust
// engine/src/engine.rs  lines 1306-1313
pub fn setup_receive_erc20_tokens_input(recipient: &Address, amount: u128) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let tail = ethabi::encode(&[
        ethabi::Token::Address(recipient.raw().0.into()),
        ethabi::Token::Uint(amount.into()),
    ]);
    [selector, tail.as_slice()].concat()
}
``` [3](#0-2) 

There is no balance-before / balance-after check. Aurora never queries its own NEP-141 balance to confirm how many tokens it actually received. For a fee-on-transfer NEP-141 token, the token contract deducts a fee during the transfer, so Aurora's actual NEP-141 balance increases by `X - fee`, but Aurora mints `X` ERC-20 tokens. The ERC-20 mirror supply is now over-collateralised relative to the NEP-141 backing.

The `EvmErc20` / `EvmErc20V2` `withdrawToNear` function burns ERC-20 tokens and calls the `ExitToNear` precompile with the full burned amount:

```solidity
// etc/eth-contracts/contracts/EvmErc20.sol  line 53-58
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);
    ...  // calls ExitToNear precompile with `amount`
}
``` [4](#0-3) 

The `ExitToNear` precompile then issues an `ft_transfer` on the NEP-141 contract for the full burned amount:

```rust
// engine-precompiles/src/native.rs  lines 630-637
format!(
    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
    exit_params.receiver_account_id,
    exit_params.amount.as_u128()
),
"ft_transfer",
``` [5](#0-4) 

Because Aurora holds fewer NEP-141 tokens than the total ERC-20 supply, the last redeemers cannot withdraw their full entitlement.

### Impact Explanation

**Critical — Direct theft of user funds / insolvency.**

Scenario:
- Fee-on-transfer NEP-141 takes a 10% fee.
- Attacker deposits 100 NEP-141 → Aurora receives 90, mints 100 ERC-20 to attacker.
- Victim deposits 100 NEP-141 → Aurora receives 90, mints 100 ERC-20 to victim.
- Aurora holds 180 NEP-141 but has 200 ERC-20 in circulation.
- Attacker redeems 100 ERC-20 → Aurora transfers 100 NEP-141 to attacker (succeeds; 80 remain).
- Victim tries to redeem 100 ERC-20 → Aurora attempts to transfer 100 NEP-141 but only holds 80 → transfer fails or victim receives only 80.

The attacker receives 100 NEP-141 having deposited only 90, stealing 10 NEP-141 from the victim. This is a direct, permanent loss of user funds.

### Likelihood Explanation

**High.** Any NEP-141 token with a transfer fee can be registered with Aurora via the permissionless `deploy_erc20_token` flow. The attacker only needs to:
1. Deploy or use an existing fee-on-transfer NEP-141.
2. Register it with Aurora.
3. Deposit and withdraw.

No privileged access is required. The entry point `ft_on_transfer` is a standard NEAR callback reachable by any NEP-141 contract. [6](#0-5) 

### Recommendation

In `receive_erc20_tokens`, replace the use of `args.amount` with the actual balance delta. Before calling `ft_transfer_call` on the NEP-141 side (or equivalently, before minting), query Aurora's NEP-141 balance, and after the transfer completes, compute `actual_received = balance_after - balance_before`. Mint only `actual_received` ERC-20 tokens.

Because `ft_on_transfer` is a callback (the transfer has already occurred by the time it is called), the simplest fix is to query Aurora's current NEP-141 balance at the start of `receive_erc20_tokens` and compare it against the stored pre-transfer balance. Alternatively, Aurora can record its NEP-141 balance before each `ft_transfer_call` and use the difference as the canonical mint amount.

### Proof of Concept

1. Deploy a NEP-141 token `FeeToken` that deducts 10% on every transfer.
2. Call `deploy_erc20_token` on Aurora to register `FeeToken` → ERC-20 mirror `FeeERC20` is created.
3. Call `FeeToken.ft_transfer_call(receiver_id=aurora, amount=1000, msg=<attacker_evm_addr>)`.
   - `FeeToken` transfers 900 to Aurora (keeps 100 as fee).
   - `FeeToken` calls `aurora.ft_on_transfer(sender=attacker, amount=1000, msg=<attacker_evm_addr>)`.
   - Aurora calls `receive_erc20_tokens` → mints **1000** `FeeERC20` to attacker.
   - Aurora's actual `FeeToken` balance: **900**.
4. Victim calls `FeeToken.ft_transfer_call(receiver_id=aurora, amount=1000, msg=<victim_evm_addr>)`.
   - Aurora receives 900 more `FeeToken` (total: 1800).
   - Aurora mints **1000** `FeeERC20` to victim.
   - Total `FeeERC20` supply: **2000**; Aurora's `FeeToken` balance: **1800**.
5. Attacker calls `FeeERC20.withdrawToNear(attacker_near_id, 1000)`.
   - Burns 1000 `FeeERC20`; `ExitToNear` precompile calls `FeeToken.ft_transfer(attacker_near_id, 1000)`.
   - Succeeds. Aurora's `FeeToken` balance: **800**.
6. Victim calls `FeeERC20.withdrawToNear(victim_near_id, 1000)`.
   - Burns 1000 `FeeERC20`; `ExitToNear` precompile calls `FeeToken.ft_transfer(victim_near_id, 1000)`.
   - **Fails** — Aurora only holds 800 `FeeToken`. Victim loses 200 `FeeToken`.

Root cause line: `engine/src/engine.rs:803` — `let amount = args.amount.as_u128();` [7](#0-6)

### Citations

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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-58)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;
```

**File:** engine-precompiles/src/native.rs (L630-637)
```rust
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
```

**File:** engine/src/contract_methods/connector.rs (L61-109)
```rust
#[named]
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
