### Title
NEP-141 Fee-on-Transfer Over-Minting: Bridge Mints More ERC-20 Than Actual NEP-141 Received, Causing Insolvency - (File: `engine/src/engine.rs`)

### Summary
When a NEP-141 token with a fee-on-transfer mechanism is bridged into Aurora, the engine mints ERC-20 tokens equal to the gross `args.amount` reported in the `ft_on_transfer` callback, rather than the net amount actually credited to Aurora's account. Over repeated deposits, the ERC-20 supply on Aurora exceeds the NEP-141 backing held by the engine, making the bridge insolvent and permanently freezing funds for the last users to exit.

### Finding Description
The NEP-141 standard's `ft_transfer_call` flow calls `ft_on_transfer(sender_id, amount, msg)` on the receiver contract with the gross transfer amount. If the NEP-141 token deducts a fee during transfer, Aurora's account receives `amount - fee` tokens, but the callback still reports `amount`.

In `engine/src/engine.rs`, `receive_erc20_tokens` reads the amount directly from the callback argument:

```rust
// engine/src/engine.rs:803
let amount = args.amount.as_u128();
```

This `amount` is then passed verbatim to `setup_receive_erc20_tokens_input`, which encodes a `mint(recipient, amount)` call to the `EvmErc20` contract:

```rust
// engine/src/engine.rs:831
setup_receive_erc20_tokens_input(&recipient, amount),
```

`setup_receive_erc20_tokens_input` (line 1306–1313) encodes the ERC-20 `mint` selector with the full `amount`, so the ERC-20 token is minted for the gross value, not the net received value.

The same pattern exists in `receive_base_tokens` for the ETH connector path:

```rust
// engine/src/engine.rs:778
let amount = Wei::new_u128(args.amount.as_u128());
```

The `ft_on_transfer` entry point in `engine/src/contract_methods/connector.rs` (lines 61–109) passes `args` directly to both functions without any reconciliation against the actual balance change.

### Impact Explanation
**Critical — Insolvency / Permanent Fund Freeze.**

Each deposit of a fee-bearing NEP-141 token over-mints ERC-20 by exactly the fee amount. After N deposits of `amount` with fee `f`, Aurora holds `N * (amount - f)` NEP-141 tokens but has minted `N * amount` ERC-20 tokens. The deficit is `N * f`.

When users call `withdrawToNear` (which burns ERC-20 and triggers `ft_transfer` on the NEP-141 contract), Aurora's NEP-141 balance is insufficient to cover all outstanding ERC-20 tokens. The last `N * f` worth of ERC-20 tokens can never be redeemed — those funds are permanently frozen.

### Likelihood Explanation
**Medium.** Any NEP-141 token with a fee-on-transfer that is registered with Aurora via `deploy_erc20_token` triggers this path. The `deploy_erc20_token` function imposes no restriction on which NEP-141 tokens can be registered. A token holder or contract deployer who registers such a token and initiates deposits is sufficient to trigger the bug — no privileged access is required. The NEP-141 fee-on-transfer pattern is a known, deployed pattern (analogous to USDT on Ethereum).

### Recommendation
In `receive_erc20_tokens` and `receive_base_tokens`, measure the actual NEP-141 balance of the Aurora account before and after the transfer, and mint ERC-20 tokens equal to the observed balance delta rather than `args.amount`. Alternatively, query the actual received amount from the NEP-141 contract and use that for minting. The `ft_on_transfer` return value (amount to refund) should also be adjusted accordingly.

### Proof of Concept

1. Deploy a NEP-141 token `fee_token.near` that charges a 1% fee on every transfer (i.e., `ft_transfer_call` of 1000 units results in the receiver getting 990 units, but `ft_on_transfer` is called with `amount = 1000`).
2. Register it with Aurora: call `deploy_erc20_token` with `fee_token.near`.
3. Alice calls `ft_transfer_call` on `fee_token.near` with `amount = 1000`, `receiver_id = aurora`, `msg = <alice_evm_address>`.
4. `fee_token.near` transfers 990 units to Aurora and calls `aurora::ft_on_transfer(sender_id=alice, amount=1000, msg=<alice_evm_address>)`.
5. Aurora executes `receive_erc20_tokens` → `let amount = args.amount.as_u128()` = **1000** → mints 1000 ERC-20 to Alice.
6. Aurora actually holds only **990** NEP-141 tokens.
7. Repeat 100 times: Aurora holds 99,000 NEP-141 but has minted 100,000 ERC-20.
8. The first 99 users can exit successfully via `withdrawToNear`. The last user's `withdrawToNear` burns their ERC-20 but Aurora's `ft_transfer` call to `fee_token.near` fails (insufficient balance) — funds are permanently frozen.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** engine/src/engine.rs (L778-778)
```rust
        let amount = Wei::new_u128(args.amount.as_u128());
```

**File:** engine/src/engine.rs (L803-803)
```rust
        let amount = args.amount.as_u128();
```

**File:** engine/src/engine.rs (L826-831)
```rust
        let result = self
            .call(
                &erc20_admin_address,
                &erc20_token,
                Wei::zero(),
                setup_receive_erc20_tokens_input(&recipient, amount),
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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L49-51)
```text
    function mint(address account, uint256 amount) public onlyAdmin {
        _mint(account, amount);
    }
```
