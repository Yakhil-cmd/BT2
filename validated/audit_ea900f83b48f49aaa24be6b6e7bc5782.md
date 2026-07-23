### Title
`protocolUnpausePool` always transitions pool to admin-paused state (1) instead of restoring to active (0), leaving swaps permanently blocked — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

When the protocol owner calls `protocolUnpausePool` on a pool that was originally **active** (state 0), the pool is unconditionally set to state 1 (