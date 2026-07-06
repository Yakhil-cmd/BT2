### Title
Missing Permission Check in `declare_operational_address` Enables Griefing of Staker Operational Address Rotation — (File: `src/staking/staking.cairo`)

### Summary
`declare_operational_address` carries no caller-identity restriction. Any unprivileged address can invoke it for an arbitrary `staker_address`, overwriting whatever eligible operational address was previously registered. An attacker can exploit this to permanently block a staker from rotating their operational key, which in turn blocks attestation and freezes unclaimed yield.

### Finding Description
The two-step operational-address rotation flow is:

1. The *intended* new operational address calls `declare_operational_address(staker_address)` — this writes the caller as the "eligible" operational address for that staker.
2. The staker calls `change_operational_address(operational_address)` — this succeeds only if `operational_address` matches the stored eligible entry.

The spec for `declare_operational_address` lists **no access-control requirement**: [1](#0-0) 

The only preconditions are that the contract is unpaused and the caller is not *already* an operational address of some other staker: [1](#0-0) 

There is no check that the caller is authorized by, or related to, the target `staker_address`. The logic section confirms the function simply **sets** (overwrites) the eligible entry: [2](#0-1) 

Because the write is unconditional, any address that is not currently registered as an operational address of any staker can call `declare_operational_address(victim_staker)` at any time and replace the legitimately declared entry with their own address.

The `change_operational_address` function then enforces `OPERATIONAL_NOT_ELIGIBLE` if the supplied address does not match the stored eligible entry: [3](#0-2) 

So the staker's `change_operational_address` call will revert, and the rotation is blocked.

### Impact Explanation
**Medium — Griefing / Temporary freezing of unclaimed yield.**

A staker whose current operational key is lost or compromised cannot rotate to a new key. Without a valid operational address, the staker cannot submit attestations. Attestations are the mechanism by which epoch rewards are credited: [4](#0-3) 

Blocking the rotation therefore blocks reward accrual for the victim staker and all delegators in their pool, constituting temporary (and potentially permanent, if the attacker persists) freezing of unclaimed yield.

### Likelihood Explanation
**Medium.** The attack requires no special privilege — only a fresh address not already registered as an operational address. On Starknet the two transactions (legitimate `declare_operational_address` and the staker's `change_operational_address`) are separate, creating a window the attacker can exploit by simply calling `declare_operational_address(victim)` between them. The attacker must repeat the call each time the victim retries, but the cost is a single cheap transaction per attempt.

### Recommendation
Add a caller-identity check to `declare_operational_address` so that only the address being declared (i.e., `get_caller_address() == the address being registered`) can register itself as eligible for a given staker. This mirrors the pattern used in `change_operational_address`, which already restricts the caller to the staker address: [5](#0-4) 

Concretely, the function should assert that `get_caller_address()` is the address that will later be passed to `change_operational_address`, not an arbitrary third party.

### Proof of Concept

```
// Normal flow (succeeds):
// 1. new_op_addr calls declare_operational_address(staker)
// 2. staker calls change_operational_address(new_op_addr)  ✓

// Attack flow:
// 1. new_op_addr calls declare_operational_address(staker)
//    → eligible[staker] = new_op_addr
// 2. attacker (fresh_addr, not any staker's operational address) calls
//    declare_operational_address(staker)
//    → eligible[staker] = fresh_addr   (overwrites, no permission check)
// 3. staker calls change_operational_address(new_op_addr)
//    → panics: OPERATIONAL_NOT_ELIGIBLE
//
// Attacker repeats step 2 on every retry, indefinitely blocking rotation.
// If staker's current operational key is lost, attestations stop,
// and unclaimed yield for the staker and all pool delegators is frozen.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** docs/spec.md (L1238-1244)
```markdown
#### pre-condition <!-- omit from toc -->
1. Staking contract is unpaused.
2. Caller address is not `operational_address` of some staker.
#### access control <!-- omit from toc -->
#### logic <!-- omit from toc -->
1. Set the caller as an eligible operational address, associated with `staker_address`.

```

**File:** docs/spec.md (L1256-1272)
```markdown
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [STAKER\_NOT\_EXISTS](#staker_not_exists)
3. [OPERATIONAL\_EXISTS](#operational_exists)
4. [OPERATIONAL\_IS\_TOKEN](#operational_is_token) 
5. [UNSTAKE\_IN\_PROGRESS](#unstake_in_progress)
6. [OPERATIONAL\_NOT\_ELIGIBLE](#operational_not_eligible)
#### pre-condition <!-- omit from toc -->
1. Staking contract is unpaused.
2. Staker (caller) exist in the contract.
3. `operational_address` is not already used by another staker.
4. Staker is not in exit window.
5. `operational_address` is eligible for the staker.
#### access control <!-- omit from toc -->
Only staker address.
#### logic <!-- omit from toc -->
1. Change registered `operational_address` for the staker.
```

**File:** docs/spec.md (L2311-2320)
```markdown
#### emits <!-- omit from toc -->
1. [Mint Request](#mint-request) - if funds are needed.
#### errors <!-- omit from toc -->
1. [CALLER\_IS\_NOT\_STAKING\_CONTRACT](#caller_is_not_staking_contract)
#### logic <!-- omit from toc -->
1. Increase `unclaimed_rewards` by `rewards`.
2. Request funds from L1 if needed.

#### access control <!-- omit from toc -->
Only staking contract.
```

**File:** src/staking/staking.cairo (L1-30)
```text
#[starknet::contract]
pub mod Staking {
    use RolesComponent::InternalTrait as RolesInternalTrait;
    use core::num::traits::zero::Zero;
    use core::option::OptionTrait;
    use core::panics::panic_with_byte_array;
    use openzeppelin::access::accesscontrol::AccessControlComponent;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc20::interface::{
        IERC20Dispatcher, IERC20MetadataDispatcher, IERC20MetadataDispatcherTrait,
    };
    use staking::constants::{K, STARTING_EPOCH, STRK_TOKEN_ADDRESS};
    use staking::errors::{GenericError, InternalError};
    use staking::pool::interface::{IPoolDispatcher, IPoolDispatcherTrait};
    use staking::reward_supplier::interface::{
        IRewardSupplierDispatcher, IRewardSupplierDispatcherTrait,
    };
    use staking::staking::errors::Error;
    use staking::staking::interface::{
        CommissionCommitment, ConfigEvents, Events, IStaking, IStakingAttestation, IStakingConfig,
        IStakingConsensus, IStakingMigration, IStakingPause, IStakingPool, IStakingRewardsManager,
        IStakingTokenManager, PauseEvents, PoolInfo, StakerInfoV1, StakerInfoV3, StakerPoolInfoV1,
        StakerPoolInfoV2, StakingContractInfoV1, TokenManagerEvents,
    };
    use staking::staking::objects::{
        AttestationInfo, AttestationInfoTrait, EpochInfo, EpochInfoTrait,
        InternalStakerInfoLatestTrait, InternalStakerPoolInfoV2, InternalStakerPoolInfoV2MutTrait,
        InternalStakerPoolInfoV2Trait, NormalizedAmount, NormalizedAmountTrait, StakerInfoV3Trait,
        StakerVersion, StakerVersionTrait, UndelegateIntentKey, UndelegateIntentValue,
        UndelegateIntentValueTrait, UndelegateIntentValueZero, VInternalStakerInfo,
```

**File:** src/staking/interface.cairo (L80-84)
```text
    /// Declare the caller address as the operational address for the given `staker_address`.
    fn declare_operational_address(ref self: TContractState, staker_address: ContractAddress);
    /// Change the operational address for the calling staker.
    fn change_operational_address(ref self: TContractState, operational_address: ContractAddress);
    /// Set the commission for all pools of the calling staker.
```
