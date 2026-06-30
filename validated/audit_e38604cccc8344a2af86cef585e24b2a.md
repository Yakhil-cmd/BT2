### Title
Unauthenticated `refund_on_error` NEAR Method Allows Arbitrary ERC-20 Minting to Any Recipient - (`engine/src/engine.rs`)

### Summary

The `refund_on_error` function in `engine/src/engine.rs` accepts a fully caller-controlled `RefundCallArgs` struct containing `recipient_address`, `erc20_address`, and `amount`. It is exposed as a public NEAR contract method (mapped as `"refund_on_error"` in the workspace). The function performs no access control check and directly mints ERC-20 tokens (or transfers ETH) to the caller-supplied `recipient_address`. Any unprivileged NEAR account can call this method to mint unbacked bridged ERC-20 tokens to any EVM address, then exit them to drain the NEP-141 bridge reserve.

### Finding Description

`engine::refund_on_error` in `engine/src/engine.rs` is the engine-level function that re-mints burned ERC-20 tokens when an `exit_to_near` bridge call fails. It is legitimately invoked only from `exit_to_near_precompile_callback` in `engine/src/contract_methods/connector.rs`, which is correctly protected by `env.assert_private_call()?`.

However, `refund_on_error` is **also** exposed as a standalone public NEAR contract method (registered as `"refund_on_error"` in `engine-workspace/src/operation.rs` and callable via `EngineContract::refund_on_error` in `engine-workspace/src/contract.rs`). The engine-level function itself contains zero access control:

```rust
pub fn refund_on_error<I: IO + Copy, E: Env, P: PromiseHandler>(
    io: I,
    env: &E,
    state: EngineState,
    args: &RefundCallArgs,   // fully caller-controlled
    handler: &mut P,
) -> EngineResult<SubmitResult> {
    let current_account_id = env.current_account_id();
    if let Some(erc20_address) = args.erc20_address {
        // ERC-20 exit; re-mint burned tokens
        let erc20_admin_address = current_address(&current_account_id);
        ...
        let refund_address = args.recipient_address;   // attacker-controlled
        let amount = U256::from_big_endian(&args.amount); // attacker-controlled
        let input = setup_refund_on_error_input(amount, refund_address);
        engine.call(&erc20_admin_address, &erc20_address, ...)
``` [1](#0-0) 

`setup_refund_on_error_input` encodes a call to the ERC-20 `mint(address, uint256)` selector, executed with the Aurora engine's own admin address as the EVM `msg.sender`: [2](#0-1) 

The `EvmErc20` and `EvmErc20V2` contracts restrict `mint` to `onlyAdmin` (the Aurora engine address), so only the engine itself can mint. When `refund_on_error` is called as a public NEAR method, the engine executes the mint on behalf of the caller with no restriction: [3](#0-2) 

The `RefundCallArgs` struct exposes all three attack-controlled fields: [4](#0-3) 

The workspace confirms `refund_on_error` is a publicly callable NEAR method: [5](#0-4) [6](#0-5) 

By contrast, the **legitimate** internal path through `exit_to_near_precompile_callback` is correctly gated: [7](#0-6) 

### Impact Explanation

**Critical — Direct theft of user funds / insolvency.**

An attacker calls `refund_on_error` with:
- `erc20_address` = any deployed bridged ERC-20 (e.g., USDC mirror)
- `recipient_address` = attacker's own EVM address
- `amount` = any value

The engine mints that amount of the bridged ERC-20 to the attacker. These tokens are unbacked (no corresponding NEP-141 was locked). The attacker then calls `withdrawToNear` on the ERC-20, which burns the EVM tokens and triggers a NEP-141 transfer from the bridge reserve to the attacker's NEAR account. This drains real NEP-141 tokens from the bridge, causing insolvency for all legitimate holders of that bridged token.

For the ETH path (`erc20_address = None`), the function transfers ETH from `exit_to_near::ADDRESS` to the attacker's address, stealing any ETH held there during in-flight exit operations. [8](#0-7) 

### Likelihood Explanation

**High.** The method is a standard public NEAR contract call requiring no special permissions, no attached deposit, and no prior state. Any NEAR account can construct and submit the call. The only prerequisite is knowing the address of a deployed bridged ERC-20 token, which is publicly discoverable on-chain.

### Recommendation

Add `env.assert_private_call()?` (or equivalent `require_owner_only`) to the NEAR contract entrypoint for `refund_on_error` in `engine/src/lib.rs`, mirroring the protection already present in `exit_to_near_precompile_callback`: [7](#0-6) 

Alternatively, remove the standalone public `refund_on_error` NEAR method entirely, since its only legitimate caller is the internal callback.

### Proof of Concept

1. Attacker identifies a bridged ERC-20 token address `erc20_addr` on Aurora.
2. Attacker calls the Aurora Engine NEAR contract method `refund_on_error` with Borsh-encoded args:
   ```
   RefundCallArgs {
       recipient_address: attacker_evm_address,
       erc20_address: Some(erc20_addr),
       amount: [0,0,...,0xFF,0xFF,...],  // large amount
   }
   ```
3. Engine executes `mint(attacker_evm_address, amount)` on `erc20_addr` as admin — succeeds.
4. Attacker calls `erc20_addr.withdrawToNear(attacker_near_account, amount)`.
5. Bridge releases `amount` of the underlying NEP-141 token to the attacker.
6. Bridge reserve is drained; remaining holders cannot redeem their tokens. [9](#0-8) [10](#0-9)

### Citations

**File:** engine/src/engine.rs (L1165-1174)
```rust
#[must_use]
pub fn setup_refund_on_error_input(amount: U256, refund_address: Address) -> Vec<u8> {
    let selector = ERC20_MINT_SELECTOR;
    let mint_args = ethabi::encode(&[
        ethabi::Token::Address(refund_address.raw().0.into()),
        ethabi::Token::Uint(amount.to_big_endian().into()),
    ]);

    [selector, mint_args.as_slice()].concat()
}
```

**File:** engine/src/engine.rs (L1176-1203)
```rust
pub fn refund_on_error<I: IO + Copy, E: Env, P: PromiseHandler>(
    io: I,
    env: &E,
    state: EngineState,
    args: &RefundCallArgs,
    handler: &mut P,
) -> EngineResult<SubmitResult> {
    let current_account_id = env.current_account_id();
    if let Some(erc20_address) = args.erc20_address {
        // ERC-20 exit; re-mint burned tokens
        let erc20_admin_address = current_address(&current_account_id);
        let mut engine: Engine<_, _> =
            Engine::new_with_state(state, erc20_admin_address, current_account_id, io, env);

        let refund_address = args.recipient_address;
        let amount = U256::from_big_endian(&args.amount);
        let input = setup_refund_on_error_input(amount, refund_address);

        engine.call(
            &erc20_admin_address,
            &erc20_address,
            Wei::zero(),
            input,
            u64::MAX,
            Vec::new(),
            Vec::new(),
            handler,
        )
```

**File:** engine/src/engine.rs (L1204-1224)
```rust
    } else {
        // ETH exit; transfer ETH back from precompile address
        let exit_address = exit_to_near::ADDRESS;
        let mut engine: Engine<_, _> =
            Engine::new_with_state(state, exit_address, current_account_id, io, env);
        let refund_address = args.recipient_address;
        let amount = Wei::new(U256::from_big_endian(&args.amount));
        engine.call(
            &exit_address,
            &refund_address,
            amount,
            Vec::new(),
            u64::MAX,
            vec![
                (exit_address.raw(), Vec::new()),
                (refund_address.raw(), Vec::new()),
            ],
            Vec::new(),
            handler,
        )
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

**File:** engine-types/src/parameters/connector.rs (L116-120)
```rust
pub struct RefundCallArgs {
    pub recipient_address: Address,
    pub erc20_address: Option<Address>,
    pub amount: RawU256,
}
```

**File:** engine-workspace/src/contract.rs (L196-208)
```rust
    #[must_use]
    pub fn refund_on_error(
        &self,
        recipient_address: Address,
        erc20_address: Option<Address>,
        amount: U256,
    ) -> CallRefundOnError {
        CallRefundOnError::call(&self.contract).args_borsh((
            recipient_address,
            erc20_address,
            amount.0,
        ))
    }
```

**File:** engine-workspace/src/operation.rs (L24-24)
```rust
    (CallRefundOnError, Call::RefundOnError),
```

**File:** engine/src/contract_methods/connector.rs (L201-204)
```rust
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;
```
