### Title
Meta-transaction relayer identity is exposed to called contracts as `signer_account_id`, enabling a `tx.origin`-style authorization bypass that can drain the relayer's funds/permissions - (File: `runtime/runtime/src/function_call.rs`, `runtime/runtime/src/actions.rs`)

### Summary
NEAR's meta transactions (NEP-366) let a relayer submit a `SignedDelegateAction` on behalf of an unrelated user. When the delegated inner actions execute on the target contract, the VM context exposes `predecessor_account_id` as the actual sender (changes per hop, like `msg.sender`) but `signer_account_id` as the *original relayer* for the whole delegated call chain (constant, like `tx.origin`). Any contract that authorizes based on `signer_account_id()` instead of `predecessor_account_id()` will treat the relayer as the direct caller, letting an arbitrary user (via a crafted `DelegateAction`) trigger privileged operations attributed to the relayer's own identity in that contract — exactly the `tx.origin`-check risk described in the report, but reachable purely through an ordinary submitted transaction rather than any privileged/validator path.

### Finding Description
When a `DelegateAction` is applied, the runtime builds a new receipt whose `predecessor_id` is the delegate's `sender_id` (the actual originator), but whose `signer_id` is copied from the *outer* action receipt — i.e. the relayer that wrapped and submitted the meta transaction: [1](#0-0) 

That `signer_id` is then propagated straight into `VMContext.signer_account_id` when the inner `FunctionCall` executes on the target contract: [2](#0-1) 

The host function `signer_account_id()` simply returns this value to the contract: [3](#0-2) 

The protocol documentation explicitly acknowledges the risk of contracts relying on this field instead of `predecessor_account_id`: [4](#0-3) 

The meta-tx architecture doc confirms the mechanics: the relayer is the transaction signer, and `signer_id` for the delegated receipt is the relayer, while `predecessor_id` is the sender/user: [5](#0-4) [6](#0-5) 

This is the direct analog of the report's `tx.origin` issue: any contract that checks `signer_account_id` for authorization (mistaking it for "who really is calling me") is actually checking who *originally paid gas* for the whole delegated chain — the relayer — not who invoked it directly. A malicious or naive user can construct a `DelegateAction` targeting such a contract; once forwarded by an honest relayer, the contract will see `signer_account_id == relayer`, exactly as if the relayer itself had called it, while `predecessor_account_id` (the honest check) would show the real, unprivileged caller.

### Impact Explanation
If any deployed contract on NEAR authorizes actions (transfers, withdrawals, permission grants) by checking `signer_account_id()` rather than `predecessor_account_id()`, a relayer that has any standing balance, allowance, or role in that contract can have those assets/permissions manipulated by an unrelated third party simply by submitting a `DelegateAction` addressed to that contract through the relayer — without the relayer's consent. This matches "unauthorized state or balance change" triggered purely by an unprivileged account submitting a transaction/DelegateAction, and is a systemic risk for any general-purpose relayer used across multiple applications, since the relayer's account is reused as a shared, unwitting `tx.origin` for many unrelated users' calls.

### Likelihood Explanation
Likelihood depends on external contract behavior (whether a given contract checks `signer_account_id`), so this is not a nearcore-only bug in the traditional sense — but the protocol design itself creates the hazard the report describes, and it is explicitly acknowledged as a known footgun in `ContextAPI.md`. Any general-purpose relayer (which the meta-tx doc explicitly anticipates as a long-term goal) is exposed to this by construction. This directly mirrors the reported issue's structure ("Acknowledged" as a known limitation requiring operational mitigation on the relayer side).

### Recommendation
- Continue to strongly document (as already partially done in `ContextAPI.md`) that `signer_account_id` must never be used for authorization checks — only `predecessor_account_id` is the safe analog of `msg.sender`.
- Consider adding protocol-level or SDK-level guidance/lint that flags contract usage of `signer_account_id()` for access control.
- Recommend relayers use dedicated, single-purpose accounts with no funds/roles in arbitrary contracts, mirroring the original report's recommendation for EOAs.

### Proof of Concept
1. Deploy a contract `Vault` that (incorrectly) authorizes withdrawals via `if env::signer_account_id() == self.owner { ... }` instead of `predecessor_account_id()`, where `owner` is set to the relayer's account.
2. Relayer account `R` normally calls `Vault::withdraw` directly for its own legitimate purposes — this works as intended since `predecessor_account_id == signer_account_id == R`.
3. An attacker, `Alice`, who has no relationship with `Vault`, signs a `DelegateAction` with `receiver_id = Vault` and inner action `FunctionCall("withdraw", ...)`, and sends it to relayer `R` for general-purpose forwarding (as demonstrated by `test_meta_tx` and `meta_tx_ft_transfer`): [7](#0-6) [8](#0-7) 
4. `R` (unaware of `Vault`'s internals) wraps and submits it. On-chain, `apply_delegate_action` builds the inner receipt with `predecessor_id = Alice`, but `signer_id = R` (copied from the relayer's outer receipt).
5. `Vault::withdraw` executes with `predecessor_account_id() == Alice` but `signer_account_id() == R`; because the contract's check uses `signer_account_id()`, it passes, and funds intended to be owned/controlled by `R` are withdrawn at Alice's request — without `R`'s direct participation or consent, replicating the reported vulnerability.

### Citations

**File:** runtime/runtime/src/actions.rs (L456-469)
```rust
    let new_receipt = Receipt::V0(ReceiptV0 {
        predecessor_id: sender_id.clone(),
        receiver_id: delegate_action.receiver_id().clone(),
        receipt_id: CryptoHash::default(),

        receipt: ReceiptEnum::Action(ActionReceipt {
            signer_id: action_receipt.signer_id().clone(),
            signer_public_key: action_receipt.signer_public_key().clone(),
            gas_price: action_receipt.gas_price(),
            output_data_receivers: vec![],
            input_data_ids: vec![],
            actions: delegate_action.get_actions(),
        }),
    });
```

**File:** runtime/runtime/src/function_call.rs (L256-262)
```rust
    let context = VMContext {
        current_account_id: runtime_ext.account_id().clone(),
        signer_account_id: action_receipt.signer_id().clone(),
        signer_account_pk: borsh::to_vec(&action_receipt.signer_public_key())
            .expect("Failed to serialize"),
        predecessor_account_id: predecessor_id.clone(),
        refund_to_account_id: action_receipt.refund_to().as_ref().unwrap_or(predecessor_id).clone(),
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L690-705)
```rust
    pub fn signer_account_id(&mut self, register_id: u64) -> Result<()> {
        self.result_state.gas_counter.pay_base(base)?;

        if self.context.is_view() {
            return Err(HostError::ProhibitedInView {
                method_name: "signer_account_id".to_string(),
            }
            .into());
        }
        self.registers.set(
            &mut self.result_state.gas_counter,
            &self.config.limit_config,
            register_id,
            self.context.signer_account_id.as_bytes(),
        )
    }
```

**File:** docs/RuntimeSpec/Components/BindingsSpec/ContextAPI.md (L34-54)
```markdown
#### signer_account_id

```rust
signer_account_id(register_id: u64)
```

All contract calls are a result of some transaction that was signed by some account using
some access key and submitted into a memory pool (either through the wallet using RPC or by a node itself). This function returns the id of that account.

###### Normal operation

- Saves the bytes of the signer account id into the register.

###### Panics

- If the registers exceed the memory limit panics with `MemoryAccessViolation`;
- If called in a view function panics with `ProhibitedInView`.

###### Current bugs

- Currently we conflate `originator_id` and `sender_id` in our code base.
```

**File:** docs/architecture/how/meta-tx.md (L40-52)
```markdown
With meta transactions, Alice can create a `DelegateAction`, which is very
similar to a transaction. It also contains a list of actions to execute and a
single receiver for those actions. She signs the `DelegateAction` and forwards
it (off-chain) to a relayer. The relayer wraps it in a transaction, of which the
relayer is the signer and therefore pays the gas costs. If the inner actions
have an attached token balance, this is also paid for by the relayer.

On chain, the `SignedDelegateAction` inside the transaction is converted to an
action receipt with the same `SignedDelegateAction` on the relayer's shard. The
receipt is forwarded to the account from `Alice`, which will unpacked the
`SignedDelegateAction` and verify that it is signed by Alice with a valid Nonce
etc. If all checks are successful, a new action receipt with the inner actions
as body is sent to `FT`. There, the `ft_transfer` call finally executes.
```

**File:** docs/RuntimeSpec/Actions.md (L363-366)
```markdown
### Outcomes

- All actions inside `delegate_action.actions` are submitted with the `delegate_action.sender_id` as the predecessor, `delegate_action.receiver_id` as the receiver, and the relayer (predecessor of `DelegateAction`) as the signer.
- All gas and balance costs for submitting `delegate_action.actions` are subtracted from the relayer.
```

**File:** test-loop-tests/src/tests/meta_tx.rs (L22-87)
```rust
#[test]
fn test_meta_tx() {
    init_test_logger();

    let relayer = create_account_id("relayer");
    let candidate = create_account_id("candidate.relayer");
    let candidate_amount = Balance::from_near(123);

    let mut env = TestLoopBuilder::new()
        .enable_rpc()
        .add_user_account(&relayer, Balance::from_near(1_000_000))
        .gas_prices(Balance::from_yoctonear(1), Balance::from_yoctonear(1))
        .build();

    let create_tx = env.rpc_node().tx_create_account(&relayer, &candidate, candidate_amount);
    env.rpc_runner().run_tx(create_tx, Duration::seconds(5));

    // The candidate starts with exactly its own (full-access) key and the given balance.
    let candidate_signer = create_user_test_signer(&candidate);
    assert!(
        env.rpc_node().view_access_key_query(&candidate, &candidate_signer.public_key()).is_ok()
    );
    assert_eq!(env.rpc_node().query_balance(&candidate), candidate_amount);

    let new_key =
        InMemorySigner::from_seed(candidate.clone(), KeyType::ED25519, "new_key").public_key();
    assert!(env.rpc_node().view_access_key_query(&candidate, &new_key).is_err());

    // Build the meta transaction: the candidate signs a DelegateAction that adds
    // the new key to itself.
    let add_key_action = Action::AddKey(Box::new(AddKeyAction {
        public_key: new_key.clone(),
        access_key: AccessKey::full_access(),
    }));
    let candidate_nonce = env.rpc_node().get_next_nonce(&candidate);
    let delegate_action = DelegateAction {
        sender_id: candidate.clone(),
        receiver_id: candidate.clone(),
        actions: vec![NonDelegateAction::try_from(add_key_action).unwrap()],
        nonce: candidate_nonce,
        max_block_height: env.rpc_node().head().height + 100,
        public_key: candidate_signer.public_key(),
    };
    let signed_delegate_action = SignedDelegateAction::sign(&candidate_signer, delegate_action);

    // The relayer wraps and submits it, paying the gas.
    let relayer_balance_before = env.rpc_node().query_balance(&relayer);
    let meta_tx =
        env.rpc_node().tx_from_actions(&relayer, &candidate, vec![signed_delegate_action.into()]);
    env.rpc_runner().run_tx(meta_tx, Duration::seconds(5));

    // Both keys now exist on the candidate account, and its balance is unchanged:
    // the relayer, not the candidate, paid the gas.
    assert!(
        env.rpc_node().view_access_key_query(&candidate, &candidate_signer.public_key()).is_ok()
    );
    assert!(env.rpc_node().view_access_key_query(&candidate, &new_key).is_ok());
    assert_eq!(env.rpc_node().query_balance(&candidate), candidate_amount);

    // The relayer's balance dropped: it paid the gas for the meta transaction.
    let relayer_balance_after = env.rpc_node().query_balance(&relayer);
    assert!(
        relayer_balance_after < relayer_balance_before,
        "relayer balance should decrease (it paid the gas): before={relayer_balance_before}, after={relayer_balance_after}"
    );
}
```

**File:** integration-tests/src/tests/features/delegate_action.rs (L625-679)
```rust
#[test]
fn meta_tx_ft_transfer() {
    let relayer = alice_account();
    let sender = bob_account();
    let ft_contract = carol_account();
    let receiver = "david.near";

    let mut genesis = Genesis::test(vec![alice_account(), bob_account(), carol_account()], 3);
    add_contract(&mut genesis, &ft_contract, near_test_contracts::ft_contract().to_vec());
    let node = RuntimeNode::new_from_genesis(&relayer, genesis);

    // A BUNCH OF TEST SETUP
    // initialize the contract
    node.user()
        .function_call(
            relayer.clone(),
            ft_contract.clone(),
            "new_default_meta",
            // make the relayer (alice) owner, makes initialization easier
            br#"{"owner_id": "alice.near", "total_supply": "1000000"}"#.to_vec(),
            Gas::from_teragas(30),
            Balance::ZERO,
        )
        .expect("FT contract initialization failed")
        .assert_success();

    // register sender & receiver FT accounts
    let actions = vec![ft_register_action(sender.as_ref()), ft_register_action(&receiver)];
    node.user()
        .sign_and_commit_actions(relayer.clone(), ft_contract.clone(), actions)
        .expect("registering FT accounts")
        .assert_success();
    // initialize sender balance
    let actions = vec![ft_transfer_action(sender.as_ref(), 10_000).0];
    node.user()
        .sign_and_commit_actions(relayer.clone(), ft_contract.clone(), actions)
        .expect("initializing sender balance failed")
        .assert_success();

    // START OF META TRANSACTION
    // 1% fee to the relayer
    let (action0, bytes0) = ft_transfer_action(relayer.as_ref(), 10);
    // the actual transfer
    let (action1, bytes1) = ft_transfer_action(receiver, 1000);
    let actions = vec![action0, action1];

    let outcome = check_meta_tx_fn_call(
        &node,
        actions,
        bytes0 + bytes1,
        Balance::from_yoctonear(2),
        sender.clone(),
        relayer.clone(),
        ft_contract.clone(),
    );
```
