### Title
`proposePoolPriceProvider` Silently Overwrites a Live Pending Proposal, Enabling Timelock Reset and Bait-and-Switch Oracle Substitution — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`proposePoolPriceProvider` in `MetricOmmPoolFactory.sol` unconditionally overwrites `pendingPriceProvider[pool]` and `pendingPriceProviderExecuteAfter[pool]` without checking whether a pending proposal is already live. A pool admin can therefore silently replace a publicly-announced provider change with a different (potentially manipulable) provider at any point before execution, simultaneously resetting the timelock clock. This is the direct structural analog of the VRF bug: a pending-state variable is overwritten without a guard, and the subsequent "fulfillment" (execution) operates on the new value rather than the one stakeholders observed.

---

### Finding Description

In `proposePoolPriceProvider` (lines 474–491 of `MetricOmmPoolFactory.sol`):

```solidity
pendingPriceProvider[pool] = newPriceProvider;          // line 488
pendingPriceProviderExecuteAfter[pool] = executeAfter;  // line 489
```

There is no preceding check such as:

```solidity
if (pendingPriceProvider[pool] != address(0)) revert PendingProviderExists();
```

The function is callable by the pool admin at any time, any number of times, with no restriction on whether