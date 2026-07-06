### Title
L2 Mint-Request Payload (`base_mint_amount`) Structurally Mismatched Against L1 Hardcoded `TOKENS_PER_MINT_REQUEST`, Permanently Breaking Reward Minting — (File: `L1/starkware/solidity/stake/RewardSupplier.sol` / `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The L1 `RewardSupplier` hardcodes the expected per-message payload value as `TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18` when computing the L2→L1 message hash to consume. The L2 `RewardSupplier` sends `base_mint_amount` (a constructor-set, immutable storage variable) as the payload. There is no on-chain enforcement that these two values are equal. If they differ, the L1 can never match the hash of any L2 mint-request message, `tick()` always returns early with zero minting, and all unclaimed staker yield is permanently frozen.

---

### Finding Description

**L2 side — `send_mint_request_to_l1_reward_supplier`:**

```cairo
fn send_mint_request_to_l1_reward_supplier(self: @ContractState) {
    let payload: Span<felt252> = array![self.base_mint_amount.read().into()].span();
    let to_address = self.l1_reward_supplier.read();
    send_message_to_l1_syscall(:to_address, :payload).unwrap_syscall();
}
```

The payload element is `base_mint_amount`, a value accepted at construction time with no setter and no constraint. [1](#0-0) 

**L1 side — `requiredMinting()` and `tick()`:**

```solidity
uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;

function requiredMinting() public view returns (uint256, uint256) {
    uint256[] memory messagePayload = new uint256[](1);
    messagePayload[0] = TOKENS_PER_MINT_REQUEST;          // hardcoded
    bytes32 msgHash = l2ToL1MsgHash(mintRequestSource(), address(this), messagePayload);
    uint256 numMsgsToConsume = Math.min(
        messagingContract().l2ToL1Messages(msgHash),
        MAX_MESSAGES_TO_PROCESS_PER_TICK
    );
    return (TOKENS_PER_MINT_REQUEST * numMsgsToConsume, numMsgsToConsume);
}
```

The hash is computed with the hardcoded constant, not with whatever the L2 actually sent. [2](#0-1) [3](#0-2) 

In `tick()`, the same hardcoded value is used again for `consumeMessageFromL2`: [4](#0-3) 

**The structural gap:** `base_mint_amount` is a free constructor parameter on L2 with no setter and no on-chain validation that it equals `TOKENS_PER_MINT_REQUEST`. The `IRewardSupplierConfig` interface exposes only `set_block_duration_config`; there is no way to correct a mismatch post-deployment. [5](#0-4) [6](#0-5) 

If `base_mint_amount ≠ TOKENS_PER_MINT_REQUEST`, every L2 mint-request message produces a hash that the L1 will never find in `l2ToL1Messages`. `requiredMinting()` always returns `(0, 0)`, `tick()` always exits early, no STRK is ever minted or bridged, and `l1_pending_requested_amount` on L2 grows without bound while the actual balance stays zero.

---

### Impact Explanation

All staker and delegator rewards depend on the L1→L2 minting pipeline. If `tick()` never mints, the L2 `RewardSupplier` balance stays at zero. When the staking contract calls `claim_rewards`, the ERC-20 transfer will fail (insufficient balance), permanently blocking every staker and delegator from receiving any yield. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

`base_mint_amount` is a free constructor argument with no default, no documentation constraint, and no on-chain check against `TOKENS_PER_MINT_REQUEST`. The L1 constant lives in a Solidity file; the L2 parameter lives in a Cairo constructor — they are maintained independently across different codebases and deployment scripts. Any redeployment, upgrade, or misconfiguration of either contract can silently introduce a mismatch. Because there is no revert or event to signal the mismatch, it may go undetected until stakers notice they cannot claim rewards.

---

### Recommendation

1. **Enforce the invariant on L2:** Add a constructor assertion (or a named constant) that `base_mint_amount` equals the expected per-message amount, and document the required value explicitly.
2. **Enforce the invariant on L1:** Replace the magic constant `TOKENS_PER_MINT_REQUEST` with a storage variable that is set during initialization and can be read/verified off-chain, or add a view function that exposes it so operators can cross-check against the L2 value.
3. **Add a setter with access control** on the L2 `RewardSupplier` for `base_mint_amount` so that a mismatch can be corrected without a full redeployment.

---

### Proof of Concept

1. Deploy L2 `RewardSupplier` with `base_mint_amount = 650_000 * 10**18` (half the L1 constant).
2. Staking proceeds normally; after one epoch the staking contract calls `update_unclaimed_rewards_from_staking_contract`, which calls `request_funds`, which calls `send_mint_request_to_l1_reward_supplier` with payload `[650_000 * 10**18]`.
3. On L1, call `tick()`. `requiredMinting()` computes `l2ToL1MsgHash(..., [1_300_000 * 10**18])` — a different hash. `l2ToL1Messages(msgHash)` returns 0. `amountToMint = 0`. `tick()` returns without minting or bridging anything.
4. The L2 `l1_pending_requested_amount` grows each epoch; the L2 balance stays zero.
5. Any staker calling `claim_rewards` triggers `RewardSupplier::claim_rewards` → `checked_transfer` → ERC-20 transfer fails (balance = 0). All yield is permanently frozen. [7](#0-6) [8](#0-7)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L111-135)
```text
    #[constructor]
    pub fn constructor(
        ref self: ContractState,
        base_mint_amount: Amount,
        minting_curve_contract: ContractAddress,
        staking_contract: ContractAddress,
        l1_reward_supplier: felt252,
        starkgate_address: ContractAddress,
        governance_admin: ContractAddress,
    ) {
        let token_address = STRK_TOKEN_ADDRESS;
        self.roles.initialize(:governance_admin);
        self.staking_contract.write(staking_contract);
        self.token_dispatcher.contract_address.write(token_address);
        // Initialize unclaimed_rewards with 1 STRK to make up for round ups of pool rewards
        // calculation in the staking contract.
        self.unclaimed_rewards.write(STRK_IN_FRIS);
        self.l1_pending_requested_amount.write(Zero::zero());
        self.base_mint_amount.write(base_mint_amount);
        self.minting_curve_dispatcher.contract_address.write(minting_curve_contract);
        self.l1_reward_supplier.write(l1_reward_supplier);
        self.starkgate_address.write(starkgate_address);
        self.avg_block_duration.write(DEFAULT_AVG_BLOCK_DURATION);
        self.block_duration_config.write(DEFAULT_BLOCK_DURATION_CONFIG);
    }
```

**File:** src/reward_supplier/reward_supplier.cairo (L301-331)
```text
        fn request_funds(ref self: ContractState, unclaimed_rewards: Amount) {
            // Read current balance.
            let token_dispatcher = self.token_dispatcher.read();
            let balance: Amount = token_dispatcher
                .balance_of(account: get_contract_address())
                .try_into()
                .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);

            // Calculate credit, which is the contract's balance plus the amount already requested
            // from L1, and the debit, which is the unclaimed rewards.
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            let credit = balance + l1_pending_requested_amount;
            let debit = unclaimed_rewards;

            // If there isn't enough credit to cover the debit + threshold, request funds.
            let base_mint_amount = self.base_mint_amount.read();
            let threshold = compute_threshold(base_mint_amount);
            if credit < debit + threshold {
                let diff = debit + threshold - credit;
                let num_msgs = ceil_of_division(dividend: diff, divisor: base_mint_amount);
                let total_amount = num_msgs * base_mint_amount;
                for _ in 0..num_msgs {
                    self.send_mint_request_to_l1_reward_supplier();
                }
                self.emit(Events::MintRequest { total_amount, num_msgs });
                l1_pending_requested_amount += total_amount;
            }

            // Commit to storage the requested amount, which is now part of the credit.
            self.l1_pending_requested_amount.write(l1_pending_requested_amount);
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L333-337)
```text
        fn send_mint_request_to_l1_reward_supplier(self: @ContractState) {
            let payload: Span<felt252> = array![self.base_mint_amount.read().into()].span();
            let to_address = self.l1_reward_supplier.read();
            send_message_to_l1_syscall(:to_address, :payload).unwrap_syscall();
        }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L10-14)
```text
uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;
uint256 constant MAX_MESSAGES_TO_PROCESS_PER_TICK = 5;

// L1_handler selector for 'update_total_supply'.
uint256 constant UPDATE_TOTAL_SUPPLY_SELECTOR = 0x3f52d976f20d8cb65b362a5df632b87dd69039597d692d7a0c65443f0e5363;
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L93-105)
```text
    function requiredMinting() public view returns (uint256, uint256) {
        uint256[] memory messagePayload = new uint256[](1);
        messagePayload[0] = TOKENS_PER_MINT_REQUEST;

        bytes32 msgHash = l2ToL1MsgHash(mintRequestSource(), address(this), messagePayload);
        // Limit the number of msgs to consume to limit.
        uint256 numMsgsToConsume = Math.min(
            messagingContract().l2ToL1Messages(msgHash),
            MAX_MESSAGES_TO_PROCESS_PER_TICK
        );

        return (TOKENS_PER_MINT_REQUEST * numMsgsToConsume, numMsgsToConsume);
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-143)
```text
    function tick() external payable {
        // Check if minting is required, and how much.
        (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

        if (amountToMint > 0) {
            // Prepare the L2->L1 mintRequest message for consumption.
            uint256[] memory messagePayload = new uint256[](1);
            messagePayload[0] = TOKENS_PER_MINT_REQUEST;

            // Consume the mintRequest messages.
            for (uint256 i = 0; i < numMsgsToConsume; i++) {
                messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload);
            }

            // Reuest minting of the requested amount from the mint manager.
            mintManager().mintRequest(token(), amountToMint);

            // Deposit the minted amount onto the bridge to the credit of `mintDestination`.
            uint256 msgFee = msg.value / 2;
            bridge().depositWithMessage{value: msgFee}(
                token(),
                amountToMint,
                mintDestination(),
                new uint256[](0)
            );
            emit ConsumedL2MintRequests(numMsgsToConsume, amountToMint);

            // Send a totalSupply update to L2MintCurve.
            msgFee = msg.value - msgFee;
            messagePayload[0] = IERC20(token()).totalSupply();
            messagingContract().sendMessageToL2{value: msgFee}(
                mintingCurve(),
                UPDATE_TOTAL_SUPPLY_SELECTOR,
                messagePayload
            );
        }
    }
```

**File:** src/reward_supplier/interface.cairo (L85-103)
```text
#[starknet::interface]
pub trait IRewardSupplierConfig<TContractState> {
    /// Sets the block duration configuration.
    ///
    /// #### Preconditions:
    /// - `block_duration_config.min_block_duration > 0`
    /// - `block_duration_config.min_block_duration <= block_duration_config.max_block_duration`
    ///
    /// #### Errors:
    /// - [`ONLY_APP_GOVERNOR`](AccessErrors::ONLY_APP_GOVERNOR)
    /// -
    /// [`INVALID_MIN_MAX_BLOCK_DURATION`](staking::reward_supplier::errors::Error::INVALID_MIN_MAX_BLOCK_DURATION)
    ///
    /// #### Access control:
    /// Only app governor.
    fn set_block_duration_config(
        ref self: TContractState, block_duration_config: BlockDurationConfig,
    );
}
```
