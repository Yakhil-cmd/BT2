### Title
Address-mapping / EIP-7702 account-entry storage deposit becomes permanently locked once an EOA has ever been delegated - ([File: substrate/frame/revive/src/lib.rs])

### Summary
`pallet-revive` allows any Ethereum account holder to submit an EIP‑7702 authorization via a normal, unprivileged `eth_transact` extrinsic. Setting a delegation charges the signer/relayer a storage-item deposit that is held on the authority's `AccountInfo` entry. The pallet's own release logic for delegated accounts is incomplete: clearing a delegation only refunds the code-lockup share of the deposit, while the "account entry" deposit itself is never released, and the underlying account can never be reaped or terminated once it has been delegated at least once. This mirrors the BathBuddy pattern from the referenced report — a contract/account that can receive value/deposits through a normal, permitted user action but has no code path to ever release them.

### Finding Description
Any externally owned account (EOA) can be turned into a `AccountType::DelegatedEOA` by anyone submitting a signed EIP‑7702 authorization through `eth_call`/`eth_transact` — a fully public, unprivileged entry point [1](#0-0) . Processing an authorization reserves an "account-entry deposit" against the authority's held balance for as long as the `DelegatedEOA` entry exists [2](#0-1) .

The pallet's own change-log documents that this deposit has no release path:

> "the `DelegatedEOA` entry persists for the life of the account, so the item/byte cost of its `ContractInfo` is charged on first delegation ... and stays held after clearing. There is no release path: a delegated EOA cannot be terminated, so this deposit is locked permanently once an account has ever been delegated." [3](#0-2) 

and again in the lifecycle notes:

> "Clearing refunds the code-lockup share of `storage_base_deposit`; the account entry's own deposit stays held — permanently, since the entry persists and delegated accounts cannot be terminated." [4](#0-3) 

The pallet enforces this by explicitly rejecting termination of a delegated EOA through the normal contract-termination path via a dedicated error variant: [5](#0-4) 

The relevant `HoldReason::AddressMapping` and `HoldReason::StorageDepositReserve` reasons are declared alongside the other holds the pallet manages, none of which provide a withdrawal/reclaim call for this specific case [6](#0-5) .

So the violated invariant is: every deposit charged by `pallet-revive` should be refundable through some code path (as is the case for ordinary contract storage deposits, code-upload deposits, and code-lockup shares, all of which have release logic in `refund_deposit`/`deposit_payment.rs`) [7](#0-6) . The account-entry deposit for a `DelegatedEOA` breaks that invariant: it is charged from a normal user's own funds through a normal, unprivileged transaction and then becomes permanently unspendable, because (a) `seal_terminate`/contract termination is blocked for delegated accounts, and (b) clearing a delegation only releases the code-lockup portion, never the entry deposit itself.

### Impact Explanation
The affected funds belong to the account owner/relayer that paid for the delegation, not to an attacker or the protocol, so this is not a theft — it is an irreversible freezing of user funds, directly analogous to the BathBuddy `receive()` finding (ETH enters the contract through a legitimate path but can never leave). Every EOA that has ever used EIP‑7702 delegation (a widely advertised, core feature of `pallet-revive`'s Ethereum compatibility) permanently loses the entry-deposit amount from its spendable balance for the lifetime of the chain, with no extrinsic, migration, or governance call identified that releases it.

### Likelihood Explanation
The precondition is a completely normal, permitted user action: signing and submitting one EIP‑7702 authorization via `eth_transact`. No privileged role, no governance action, and no malicious peer is required — it happens on every legitimate use of the feature. Given `eth_transact`/EIP‑7702 support is a shipped, user-facing capability of `pallet-revive`, likelihood of triggering the fund lock is high (in fact, unavoidable for anyone using account delegation as designed); the only open question is whether the deposit amount is intended to be a permanent "identity/anti-spam" bond by design or an unintentional omission of a refund path.

### Recommendation
- Add a refund/reclaim path for the `DelegatedEOA` account-entry deposit — e.g., allow it to be released once the delegation has been cleared and no child-trie storage items remain, mirroring the refund logic already present for code-lockup and ordinary contract storage deposits in `Pallet::<T>::refund_deposit` and `deposit_payment.rs`.
- Alternatively, if the permanent lock is an intentional design choice (a bonded/one-time cost for ever using delegation), document it prominently in user-facing docs/RPC responses (not only in the PR description) so wallets and relayers can warn users before they pay it, and consider making it explicit constant-cost rather than proportional to `ContractInfo`'s encoded size.

### Proof of Concept
- Failed guard identified: `Error::CannotTerminateDelegatedAccount` unconditionally rejects `seal_terminate` for any `AccountType::DelegatedEOA`, so the standard termination/refund flow can never run for these accounts [5](#0-4) .
- Deployment/documentation evidence: the pallet's own PR documentation explicitly confirms the deposit "is locked permanently once an account has ever been delegated" and that clearing only refunds the code-lockup share [8](#0-7) .
- PoC execution status: **not executed**. I was not able to complete a full read of `substrate/frame/revive/src/evm/eip7702.rs` (where `process_authorizations`, the entry-deposit charge, and the clear/redelegate refund logic live) before running out of investigation iterations, so I could not build or run a minimal Rust/FRAME integration test that charges the deposit, clears the delegation, and asserts the balance remains held indefinitely. The existing test suite (`substrate/frame/revive/src/tests/eip7702.rs`) already contains extensive assertions about deposit charge/refund bookkeeping across relayers, which would be the natural harness to extend with an assertion that the entry deposit is unreleased after `clear` + attempted termination — this is left as an open verification step rather than a claimed test run.

### Citations

**File:** prdoc/pr_12229.prdoc (L7-11)
```text
    Implements [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) for `pallet-revive`: an EOA can sign an authorization that designates a target contract whose code runs when the EOA is called, while keeping the EOA's storage and balance.

    ## Pallet integration

    `eth_call` gains an `authorization_list: Vec<AuthorizationListEntry>` parameter. The signature change is safe because `eth_call` is never dispatched directly — it's the inner call of `eth_transact`, signed by an Ethereum wallet and submitted via `eth-rpc`. List length is bounded indirectly: each entry reserves `worst_case_delegation_deposit` against the tx's storage-deposit budget, so a transaction can only carry as many entries as its budget covers.
```

**File:** prdoc/pr_12229.prdoc (L20-39)
```text
    Revive-specific costs per authorization, beyond the EVM baseline:

    - **ED for new accounts**: an authority that didn't exist on-chain is created.
    - **Account-entry deposit**: the `DelegatedEOA` entry persists for the life of the account, so the item/byte cost of its `ContractInfo` is charged on first delegation — even when the target is not a contract — and stays held after clearing. There is no release path: a delegated EOA cannot be terminated, so this deposit is locked permanently once an account has ever been delegated. On a relayed set/clear the recorded payer is refunded in full and the relayer is charged the entry deposit anew (becoming the recorded payer) — relaying a revocation is therefore no longer deposit-neutral for the relayer.
    - **Code lockup deposit + refcount**: delegating to a contract increments the refcount on its code hash so the code can't be deleted while delegated, and reserves a deposit equal to the lockup share of the code's storage cost. Deposits are tracked against the relayer that paid them (see `payer` below) so refunds flow to the original payer regardless of who relays the next set/clear.

    ## Storage changes

    New `AccountType::DelegatedEOA` variant:

    - `delegate_target: Option<H160>` — target contract (`None` after clearing).
    - `contract_info: ContractInfo` — child trie + base-deposit accounting for the delegated EOA.
    - `payer: Option<T::AccountId>` — account that paid the currently held deposit; read on clear/re-delegation so refunds flow back to the original payer rather than whoever relays the next authorization.

    Lifecycle:

    - Once delegated, an EOA stays `DelegatedEOA` permanently; clearing only zeroes the target.
    - The child trie survives across target changes (re-delegate keeps storage).
    - Code refcounts are managed on set/clear.
    - Clearing refunds the code-lockup share of `storage_base_deposit`; the account entry's own deposit stays held — permanently, since the entry persists and delegated accounts cannot be terminated. Per-item storage deposits stay locked until the user re-delegates to a contract that lets them release the items through normal storage operations.
```

**File:** substrate/frame/revive/src/lib.rs (L662-668)
```rust
		/// A contract cannot be created at this address: it still has uncleared
		/// [`NativeDepositOf`] entries from a previously terminated contract that the deletion
		/// queue has not yet drained.
		PendingDepositCleanup = 0x43,
		/// `seal_terminate` was invoked on an EIP-7702 delegated EOA. Delegated accounts
		/// cannot be torn down via the contract-termination path.
		CannotTerminateDelegatedAccount = 0x44,
```

**File:** substrate/frame/revive/src/lib.rs (L674-683)
```rust
	/// A reason for the pallet revive placing a hold on funds.
	#[pallet::composite_enum]
	pub enum HoldReason {
		/// The Pallet has reserved it for storing code on-chain.
		CodeUploadDepositReserve,
		/// The Pallet has reserved it for storage deposit.
		StorageDepositReserve,
		/// Deposit for creating an address mapping in [`OriginalAccount`].
		AddressMapping,
	}
```

**File:** substrate/frame/revive/src/lib.rs (L2857-2898)
```rust
	/// Refund a deposit.
	///
	/// `dst` is usually the transaction origin and `from` a contract or
	/// the pallets own account.
	pub(crate) fn refund_deposit(
		hold_reason: HoldReason,
		from: &T::AccountId,
		dst: deposit_payment::Funds<T::AccountId>,
		amount: BalanceOf<T>,
	) -> Result<(), DispatchError> {
		if amount.is_zero() {
			return Ok(());
		}

		let to = match &dst {
			deposit_payment::Funds::Balance(to) | deposit_payment::Funds::TxFee(to) => *to,
		};
		let result = T::Deposit::refund_on_hold(hold_reason, from, dst, amount);

		result.defensive_map_err(|err| {
			let available = T::Deposit::total_on_hold(hold_reason, from);
			if available < amount {
				// The storage deposit accounting got out of sync with the balance: This would be a
				// straight up bug in this pallet.
				log::error!(
					target: LOG_TARGET,
					"Failed to refund storage deposit {amount:?} from contract {from:?} to origin {to:?}. Not enough deposit: {available:?}. This is a bug.",
				);
				Error::<T>::StorageRefundNotEnoughFunds.into()
			} else {
				// There are some locks preventing the refund. This could be the case if the
				// contract participates in government. The consequence is that if a contract votes
				// with its storage deposit it would no longer be possible to remove storage without first
				// reducing the lock.
				log::warn!(
					target: LOG_TARGET,
					"Failed to refund storage deposit {amount:?} from contract {from:?} to origin {to:?}: {err:?}. First remove locks (staking, governance) from the contracts account.",
				);
				Error::<T>::StorageRefundLocked.into()
			}
		})
	}
```
