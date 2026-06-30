### Title
`ExitToNear` Precompile Refunds ETH/ERC-20 Tokens to Caller-Supplied `refund_address` Instead of Actual Token Owner (`context.caller`) — (`engine-precompiles/src/native.rs`)

---

### Summary

When the `error_refund` feature is enabled, the `ExitToNear` precompile accepts a `refund_address` directly from user-supplied calldata (bytes 1–20 of the input). If the downstream NEAR-side `ft_transfer` promise fails, the refund (ETH or re-minted ERC-20 tokens) is sent to this caller-controlled `refund_address` rather than to `context.caller` — the address that actually provided the funds. There is no validation that `refund_address == context.caller`. Any contract (wrapper, zap, aggregator) that calls the precompile on behalf of a user and sets `refund_address` to the intended NEAR recipient's EVM address (or any address other than the actual sender) will cause the user's funds to be permanently redirected on failure.

---

### Finding Description

**Input parsing — `parse_input`**

When `error_refund` is compiled in, `parse_input` extracts bytes 1–20 of the raw calldata as `refund_address` with no constraint that it equals `context.caller`: [1](#0-0) 

**Storing the unchecked address — `ExitToNearParams`**

Both `BaseTokenParams` and `Erc20TokenParams` store this caller-supplied value verbatim: [2](#0-1) 

**Building the refund args — `refund_call_args`**

`refund_call_args` copies `params.refund_address` directly into `RefundCallArgs::recipient_address` without comparing it to `context.caller`: [3](#0-2) 

**Executing the refund — `refund_on_error`**

When the NEAR promise fails, `exit_to_near_precompile_callback` calls `refund_on_error`, which mints ERC-20 tokens or transfers ETH to `args.recipient_address` (i.e., the unchecked `refund_address`): [4](#0-3) 

**ETH value is taken from `context.caller`, not from `refund_address`**

For the base-token (ETH) path, the amount consumed is `context.apparent_value` — the ETH sent by `context.caller`. The refund, however, goes to `refund_address`: [5](#0-4) 

---

### Impact Explanation

If `refund_address ≠ context.caller`:

- **ETH (base token) exit:** The user's ETH (`context.apparent_value`) is deducted from `context.caller`. On NEAR-side failure, that ETH is transferred to `refund_address`. The actual sender receives nothing. Funds are permanently lost.
- **ERC-20 exit:** The ERC-20 contract burns tokens from the user and calls the precompile. On failure, the burned tokens are re-minted to `refund_address` instead of the original token holder. Funds are permanently lost.

This constitutes **direct theft / permanent loss of user funds** — matching the Critical impact tier.

---

### Likelihood Explanation

The `error_refund` feature must be compiled in (it is a named production feature, not test-only).

The realistic trigger is any **wrapper or aggregator contract** that calls the `ExitToNear` precompile on behalf of a user and sets `refund_address` to the intended NEAR-side recipient's EVM address (or any address other than the actual sender) — exactly the pattern seen in the NFTX zap. The NEAR-side `ft_transfer` can fail for ordinary reasons (unregistered account, insufficient storage deposit, etc.), which is a documented and tested failure mode. [6](#0-5) 

---

### Recommendation

Enforce that `refund_address` equals `context.caller` inside the precompile's `run` method, or remove the ability for callers to supply an arbitrary `refund_address` and always derive it from `context.caller`:

```rust
// After parsing refund_address:
#[cfg(feature = "error_refund")]
if refund_address != Address::new(context.caller) {
    return Err(ExitError::Other(Cow::from("ERR_INVALID_REFUND_ADDRESS")));
}
```

Alternatively, ignore the caller-supplied `refund_address` entirely and always use `Address::new(context.caller)` when constructing `RefundCallArgs`.

---

### Proof of Concept

1. Deploy a wrapper contract `Zap` on Aurora EVM.
2. `Zap.exitForUser(nearRecipient, evmRecipient)`:
   - Accepts ETH from `msg.sender` (Alice).
   - Constructs `ExitToNear` calldata with `flag=0x00`, `refund_address = evmRecipient` (Bob's address), `receiver_account_id = nearRecipient` (an unregistered NEAR account).
   - Calls the `ExitToNear` precompile at `exit_to_near::ADDRESS` forwarding Alice's ETH.
3. The NEAR-side `ft_transfer` to `nearRecipient` fails (account not registered).
4. `exit_to_near_precompile_callback` fires; `refund_on_error` transfers Alice's ETH to Bob's EVM address.
5. Alice's ETH is permanently gone; Bob received ETH he did not pay for. [7](#0-6) [8](#0-7)

### Citations

**File:** engine-precompiles/src/native.rs (L449-455)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
```

**File:** engine-precompiles/src/native.rs (L536-553)
```rust
        None => Ok((
            eth_connector_account_id,
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            format!(
                r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                exit_params.receiver_account_id,
                context.apparent_value.as_u128()
            ),
            events::ExitToNear::Legacy(ExitToNearLegacy {
                sender: Address::new(context.caller),
                erc20_address: events::ETH_ADDRESS,
                dest: exit_params.receiver_account_id.to_string(),
                amount: context.apparent_value,
            }),
            "ft_transfer".to_string(),
            None,
        )),
```

**File:** engine-precompiles/src/native.rs (L682-697)
```rust
#[cfg_attr(test, derive(Debug, PartialEq))]
struct BaseTokenParams<'a> {
    #[cfg(feature = "error_refund")]
    refund_address: Address,
    receiver_account_id: AccountId,
    message: Option<Message<'a>>,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
struct Erc20TokenParams<'a> {
    #[cfg(feature = "error_refund")]
    refund_address: Address,
    receiver_account_id: AccountId,
    amount: U256,
    message: Option<Message<'a>>,
}
```

**File:** engine-precompiles/src/native.rs (L699-725)
```rust
#[cfg(feature = "error_refund")]
#[allow(clippy::unnecessary_wraps)]
fn refund_call_args(
    params: &ExitToNearParams,
    event: &events::ExitToNear,
) -> Option<RefundCallArgs> {
    Some(RefundCallArgs {
        recipient_address: match params {
            ExitToNearParams::BaseToken(params) => params.refund_address,
            ExitToNearParams::Erc20TokenParams(params) => params.refund_address,
        },
        erc20_address: match params {
            ExitToNearParams::BaseToken(_) => None,
            ExitToNearParams::Erc20TokenParams(_) => {
                let erc20_address = match event {
                    events::ExitToNear::Legacy(legacy) => legacy.erc20_address,
                    events::ExitToNear::Omni(omni) => omni.erc20_address,
                };
                Some(erc20_address)
            }
        },
        amount: types::u256_to_arr(&match event {
            events::ExitToNear::Legacy(legacy) => legacy.amount,
            events::ExitToNear::Omni(omni) => omni.amount,
        }),
    })
}
```

**File:** engine-precompiles/src/native.rs (L739-742)
```rust
        #[cfg(feature = "error_refund")]
        let (refund_address, input) = parse_input(input)?;
        #[cfg(not(feature = "error_refund"))]
        let input = parse_input(input)?;
```

**File:** engine-precompiles/src/native.rs (L778-785)
```rust
#[cfg(feature = "error_refund")]
fn parse_input(input: &[u8]) -> Result<(Address, &[u8]), ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    let mut buffer = [0; 20];
    buffer.copy_from_slice(&input[1..21]);
    let refund_address = Address::from_array(buffer);
    Ok((refund_address, &input[21..]))
}
```

**File:** engine/src/engine.rs (L1184-1224)
```rust
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

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```
