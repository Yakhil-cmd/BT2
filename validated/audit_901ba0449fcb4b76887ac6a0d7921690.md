### Title
ETH Permanently Frozen in Precompile Address When Refund Target Is a Contract Without Fallback — (`engine/src/engine.rs`)

---

### Summary

When the `ExitToNear` precompile's NEAR-side `ft_transfer` promise fails and the `error_refund` feature is enabled, `refund_on_error` unconditionally calls `engine.call()` with the full ETH amount and empty calldata to the `refund_address`. If that address is an EVM contract without a fallback or receive function, the EVM call reverts, the refund is lost, and the ETH is permanently frozen inside the `exit_to_near::ADDRESS` precompile account — with no recovery path.

---

### Finding Description

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) handles ETH bridge-out from Aurora to NEAR. When the base-token (ETH) exit path is taken, the precompile:

1. Deducts ETH from the caller's EVM balance (transferred to `exit_to_near::ADDRESS`).
2. Schedules a NEAR `ft_transfer` promise to the eth-connector.
3. Registers a callback `exit_to_near_precompile_callback` that, on promise failure, calls `refund_on_error`.

`refund_on_error` in `engine/src/engine.rs` handles the ETH refund branch as follows:

```rust
// ETH exit; transfer ETH back from precompile address
let exit_address = exit_to_near::ADDRESS;
let mut engine: Engine<_, _> =
    Engine::new_with_state(state, exit_address, current_account_id, io, env);
let refund_address = args.recipient_address;
let amount = Wei::new(U256::from_big_endian(&args.amount));
engine.call(
    &exit_address,
    &refund_address,   // ← unconditional call, no fallback check
    amount,
    Vec::new(),        // ← empty calldata
    u64::MAX,
    vec![
        (exit_address.raw(), Vec::new()),
        (refund_address.raw(), Vec::new()),
    ],
    Vec::new(),
    handler,
)
``` [1](#0-0) 

This is an unconditional EVM `CALL` with value and empty calldata to `refund_address`. If `refund_address` is an EVM contract that has no fallback or receive function, the EVM call reverts. The function then returns an error, and `exit_to_near_precompile_callback` propagates `ERR_REFUND_FAILURE`:

```rust
} else if let Some(args) = args.refund {
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    if !refund_result.status.is_ok() {
        return Err(errors::ERR_REFUND_FAILURE.into());
    }
    Some(refund_result)
}
``` [2](#0-1) 

At this point the ETH is irrecoverably stuck in `exit_to_near::ADDRESS`. The original EVM state change (deducting ETH from the caller) was committed in the first NEAR receipt; the callback failure does not roll it back.

The `refund_address` is caller-supplied in the precompile input and parsed unconditionally:

```rust
#[cfg(feature = "error_refund")]
let (refund_address, input) = parse_input(input)?;
``` [3](#0-2) 

There is no guard that checks whether `refund_address` is capable of receiving a plain ETH transfer before the call is made.

Additionally, `exit_base_token_to_near` performs no zero-value guard on `context.apparent_value`:

```rust
None => Ok((
    eth_connector_account_id,
    format!(
        r#"{{"receiver_id":"{}","amount":"{}"}}"#,
        exit_params.receiver_account_id,
        context.apparent_value.as_u128()   // no zero check
    ),
    "ft_transfer".to_string(),
    None,
)),
``` [4](#0-3) 

This contrasts with the ERC-20 exit path, which explicitly rejects non-zero `apparent_value` to prevent ETH from being locked in the precompile address:

```rust
if context.apparent_value != U256::zero() {
    return Err(ExitError::Other(Cow::from(
        "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
    )));
}
``` [5](#0-4) 

The symmetrical protection (rejecting zero-value on the base-token path) is absent.

---

### Impact Explanation

When the `error_refund` feature is enabled and the NEAR-side `ft_transfer` fails:

- ETH is already deducted from the caller's EVM balance and held in `exit_to_near::ADDRESS`.
- The refund `engine.call()` to a contract without fallback/receive reverts.
- The ETH remains permanently frozen in `exit_to_near::ADDRESS` with no recovery mechanism.

**Impact: Critical — Permanent freezing of user funds.**

---

### Likelihood Explanation

Any EVM contract (multisig, vault, DeFi protocol) that:
1. Calls the `ExitToNear` precompile with non-zero ETH, and
2. Does not implement a Solidity `fallback` or `receive` function,

is vulnerable if the NEAR-side `ft_transfer` ever fails (e.g., due to insufficient NEP-141 balance on the Aurora engine account, NEAR network congestion, or any other transient failure). This is a realistic scenario for smart-contract wallets and protocol-level bridge integrations.

---

### Recommendation

1. **Guard against zero-value exits**: In `exit_base_token_to_near`, reject calls where `context.apparent_value == U256::zero()` before scheduling any NEAR promise, mirroring the guard already present in `exit_erc20_token_to_near`.

2. **Guard the refund call**: In `refund_on_error`, before calling `engine.call()` with ETH to `refund_address`, check whether the address has EVM code. If it does, use a try-call pattern and, on failure, credit the ETH to the address's balance directly via `set_balance` rather than via a `CALL` opcode — or emit an event so the funds can be claimed via a separate recovery method.

3. **Alternative**: Store the pending refund amount in contract storage and expose a `claim_refund` method that the user can call from an EOA, bypassing the fallback/receive requirement.

---

### Proof of Concept

**Setup**: Deploy an Aurora EVM contract `NoFallback` with no `fallback` or `receive` function. Fund it with ETH on Aurora. From `NoFallback`, call the `ExitToNear` precompile (address `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) with non-zero ETH value and a valid NEAR recipient.

**Trigger failure**: Ensure the NEAR-side `ft_transfer` fails (e.g., drain the Aurora engine's NEP-141 balance beforehand, as demonstrated in the existing test `test_exit_to_near_eth_refund`).

**Observe**:
- `exit_to_near_precompile_callback` fires with a failed promise result.
- `refund_on_error` calls `engine.call(exit_address → NoFallback, amount, [])`.
- The EVM call reverts because `NoFallback` has no fallback function.
- `ERR_REFUND_FAILURE` is returned.
- The ETH remains in `exit_to_near::ADDRESS` permanently.
- `NoFallback`'s EVM balance is never restored.

The existing test infrastructure in `engine-tests/src/tests/erc20_connector.rs` (`test_exit_to_near_eth_refund`) already demonstrates the refund path; replacing the signer EOA with a `NoFallback` contract reproduces the freeze. [6](#0-5)

### Citations

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

**File:** engine-precompiles/src/native.rs (L576-580)
```rust
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }
```

**File:** engine-precompiles/src/native.rs (L739-742)
```rust
        #[cfg(feature = "error_refund")]
        let (refund_address, input) = parse_input(input)?;
        #[cfg(not(feature = "error_refund"))]
        let input = parse_input(input)?;
```

**File:** engine-tests/src/tests/erc20_connector.rs (L717-781)
```rust
    #[tokio::test]
    async fn test_exit_to_near_eth_refund() {
        // Test the case where the ft_transfer promise from the exit call fails;
        // ensure ETH is refunded.

        let TestExitToNearEthContext {
            signer,
            signer_address,
            chain_id,
            tester_address,
            aurora,
        } = test_exit_to_near_eth_common().await.unwrap();
        let exit_account_id = "any.near";

        // Make the ft_transfer call fail by draining the Aurora account
        let result = aurora
            .ft_transfer(
                &"tmp.near".parse().unwrap(),
                u128::from(INITIAL_ETH_BALANCE).into(),
                &None,
            )
            .max_gas()
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await
            .unwrap();
        assert!(result.is_success());

        // call exit to near
        let input = build_input(
            "withdrawEthToNear(bytes)",
            &[ethabi::Token::Bytes(exit_account_id.as_bytes().to_vec())],
        );
        let tx = utils::create_eth_transaction(
            Some(tester_address),
            Wei::new_u64(ETH_EXIT_AMOUNT),
            input,
            Some(chain_id),
            &signer.secret_key,
        );
        let result = aurora
            .submit(rlp::encode(&tx).to_vec())
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(result.is_success());

        // check balances
        assert_eq!(
            nep_141_balance_of(aurora.as_raw_contract(), &exit_account_id.parse().unwrap()).await,
            0
        );

        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);

        assert_eq!(
            eth_balance_of(signer_address, &aurora).await,
            expected_balance
        );
    }
```
