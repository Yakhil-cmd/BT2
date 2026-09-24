### Title
CREATE1 contract-address prediction returned by dry-run/RPC calls diverges from the real on-chain deployment address in `pallet-revive` - ([File: substrate/frame/revive/src/exec.rs])

### Summary
`pallet_revive`'s `Stack::new_frame` derives the CREATE1 (no-salt) address for a contract instantiation from `account_nonce`, adjusting it by `-1` whenever `origin_is_caller` is `true`, on the theory that a real signed extrinsic has already incremented the nonce pre-dispatch. However `origin_is_caller` is hard-coded to `true` for every top-level call constructed via `Stack::new`, including calls made through the dry-run/RPC path (`exec_config.is_dry_run`), where the nonce is **not** pre-incremented. As a result, an address predicted via a dry run (e.g. `eth_call`/runtime-API simulation of a contract-creation transaction) is computed with `nonce - 1`, while the real, later-submitted extrinsic computes the address with the correct `nonce`. The two addresses differ, mirroring the reported EVM bug where a "predict address" helper omits a transformation that the real creation path applies, so the predicted and the actual deployment address diverge.

### Finding Description
`FrameArgs::Instantiate` computes the address in `substrate/frame/revive/src/exec.rs`: [1](#0-0) 

The comment explicitly states the `-1` adjustment is only valid "the Nonce from the origin has been incremented pre-dispatch" — i.e. only true for a real extrinsic dispatch, not for a dry run/runtime-API simulation (where no pre-dispatch signed-extension nonce increment ever happens). The flag that supposedly encodes this distinction, `origin_is_caller`, is however hard-coded to `true` unconditionally for every top-level frame in `Stack::new`: [2](#0-1) 

`exec_config.is_dry_run` is available at this exact call site (it is already consulted a few lines later to set up the pending-block timestamp override for dry runs): [3](#0-2) 

...but it is never consulted to gate the nonce/`origin_is_caller` logic used for address derivation. This is precisely the class of bug documented (and supposedly fixed) upstream in `prdoc/stable2506/pr_8504.prdoc`, which states the fix adds a check `if origin_is_caller && matches!(exec_context, ExecContext::Transaction)`. A repo-wide search shows `ExecContext` and the `exec_context`-gated check exist only in that prdoc description — the corresponding code in `exec.rs` is absent: [4](#0-3) 

So in this snapshot the fix described in the prdoc has not actually been applied to `exec.rs`; the vulnerable pre-fix logic is still present and reachable by any unprivileged caller who invokes a dry-run instantiate (e.g. through `eth_call`/`eth_estimateGas`/the `ContractsApi::instantiate` runtime API used by wallets and tooling to predict a contract's future address before broadcasting the real transaction).

This is the direct analog of the external report: `predictFeeDistributorAddress` fails to account for a transformation (default value substitution) that the real creation path (`createFeeDistributor`) applies, so the address a caller computes ahead of time does not match the address actually used to store/receive funds. Here, the dry-run address-prediction path fails to account for the nonce-increment semantics that the real dispatch path applies, so the address a caller predicts ahead of time (via dry run) does not match the address the contract is actually deployed to when the real extrinsic executes.

### Impact Explanation
Any off-chain tool, wallet, or smart contract that uses the dry-run/RPC path to predict a to-be-deployed contract's address (a common "counterfactual deployment" pattern — pre-funding an address before the contract creation transaction lands, or a factory contract recording the predicted address for later bookkeeping) will compute an address that is `nonce - 1` derived instead of `nonce` derived. When the real instantiate transaction is later dispatched, the contract lands at a different address than predicted. Any value transferred to the mispredicted address (native balance, or storage/bookkeeping keyed by that address in an off-chain or on-chain system) is stranded at an account that will never host the intended contract — funds sent there are effectively locked, matching the "funds lock" impact of the original report.

### Likelihood Explanation
The bug is unconditionally triggered whenever a CREATE1 (no-salt) instantiate is dry-run/simulated through the RPC/runtime-API path — no privileged role, governance, or malicious peer is required; it is purely a consequence of ordinary, permitted usage (dry-running a contract deployment to obtain its future address, which is a documented and expected wallet/tooling workflow for `pallet-revive`/EVM-style deployments). The precondition (`salt == None`, i.e., CREATE1 semantics) is common since CREATE2 requires an explicit salt.

### Recommendation
Gate the `-1` nonce adjustment on both `origin_is_caller` and an explicit "real transaction dispatch" context (e.g., reintroduce/apply the `ExecContext`/`exec_config.is_dry_run` check described in `prdoc/stable2506/pr_8504.prdoc`) inside `Stack::new_frame`'s `FrameArgs::Instantiate` branch, so that dry-run/RPC address predictions use the un-decremented nonce consistently with the nonce that will actually be used at real dispatch time.

### Proof of Concept
Not executed against a live network per instructions; evidence is a static-analysis reproduction of the guard failure:
- Guard checked: `origin_is_caller` in `exec.rs:1208` — found to be unconditionally `true` from `exec.rs:1034`, with no consultation of `exec_config.is_dry_run` (present and used two lines later at `exec.rs:1045-1046` for an unrelated purpose).
- Confirmed absence of the upstream fix: `grep` for `ExecContext` and `origin_is_caller` across the repo shows these identifiers only inside `prdoc/stable2506/pr_8504.prdoc` (the changelog claiming the fix), and not inside `substrate/frame/revive/src/exec.rs`, i.e. the fix commit's code changes are not present in this snapshot.
- A minimal integration test to demonstrate divergence would call the `ContractsApi`/`eth_call` dry-run instantiate for account `A` at nonce `N` (expect predicted address `create1(deployer, N-1)`), then dispatch the real `instantiate_with_code`/`eth_transact` extrinsic for the same account (which lands at `create1(deployer, N)`), and assert `predicted_addr != actual_addr` — this was not executed in this session, only derived from reading the exact code paths cited above.

### Citations

**File:** substrate/frame/revive/src/exec.rs (L1019-1041)
```rust
	fn new(
		args: FrameArgs<T, E>,
		origin: Origin<T>,
		transaction_meter: &'a mut TransactionMeter<T>,
		value: U256,
		exec_config: &'a ExecConfig<T>,
		input_data: &Vec<u8>,
	) -> Result<Option<(Self, ExecutableOrPrecompile<T, E, Self>)>, ExecError> {
		origin.ensure_mapped()?;
		let Some((first_frame, executable)) = Self::new_frame(
			args,
			value,
			transaction_meter,
			&CallResources::NoLimits,
			false,
			true,
			input_data,
			exec_config,
		)?
		else {
			return Ok(None);
		};

```

**File:** substrate/frame/revive/src/exec.rs (L1042-1051)
```rust
		let mut timestamp = T::Time::now();
		let mut block_number = <frame_system::Pallet<T>>::block_number();
		// if dry run with timestamp override is provided we simulate the run in a `pending` block
		if let Some(timestamp_override) =
			exec_config.is_dry_run.as_ref().and_then(|cfg| cfg.timestamp_override)
		{
			block_number = block_number.saturating_add(1u32.into());
			// Delta is in milliseconds; increment timestamp by one second
			let delta = 1000u32.into();
			timestamp = cmp::max(timestamp.saturating_add(delta), timestamp_override);
```

**File:** substrate/frame/revive/src/exec.rs (L1197-1214)
```rust
			FrameArgs::Instantiate { sender, executable, salt, input_data } => {
				let deployer = T::AddressMapper::to_address(&sender);
				let account_nonce = <System<T>>::account_nonce(&sender);
				let address = if let Some(salt) = salt {
					address::create2(&deployer, executable.code(), input_data, salt)
				} else {
					use sp_runtime::Saturating;
					address::create1(
						&deployer,
						// the Nonce from the origin has been incremented pre-dispatch, so we
						// need to subtract 1 to get the nonce at the time of the call.
						if origin_is_caller {
							account_nonce.saturating_sub(1u32.into()).saturated_into()
						} else {
							account_nonce.saturated_into()
						},
					)
				};
```

**File:** prdoc/stable2506/pr_8504.prdoc (L1-41)
```text
title: Fix generated address returned by Substrate RPC runtime call
doc:
- audience: Runtime Dev
  description: |-
    ## Description

    When dry-running a contract deployment through the runtime API, the returned address does not match the actual address that will be used when the transaction is submitted. This inconsistency occurs because the address derivation logic doesn't properly account for the difference between transaction execution and dry-run execution contexts.

    The issue stems from the `create1` address derivation logic in `exec.rs`:

    ```rust
    address::create1(
        &deployer,
        // the Nonce from the origin has been incremented pre-dispatch, so we
        // need to subtract 1 to get the nonce at the time of the call.
        if origin_is_caller {
            account_nonce.saturating_sub(1u32.into()).saturated_into()
        } else {
            account_nonce.saturated_into()
        },
    )
    ```

    The code correctly subtracts 1 from the account nonce during a transaction execution (because the nonce is incremented pre-dispatch), but doesn't account for execution context - whether it's a real transaction or a dry run through the RPC.

    ## Review Notes

    This PR adds a new condition to check for the `ExecContext` when calculating the nonce for address derivation:

    ```rust
    address::create1(
        &deployer,
        // the Nonce from the origin has been incremented pre-dispatch, so we
        // need to subtract 1 to get the nonce at the time of the call.
        if origin_is_caller && matches!(exec_context, ExecContext::Transaction) {
            account_nonce.saturating_sub(1u32.into()).saturated_into()
        } else {
            account_nonce.saturated_into()
        },
    )
    ```
```
