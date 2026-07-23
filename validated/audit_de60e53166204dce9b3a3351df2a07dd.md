I was unable to complete the required code-level analysis. The `read_file` tool failed for all attempted reads of the production contract files:

- `metric-core/contracts/MetricOmmPool.sol`
- `metric-core/contracts/MetricOmmPoolFactory.sol`
- `metric-core/contracts/MetricOmmPoolDeployer.sol`
- `smart-contracts-poc/contracts/PriceProviderFactory.sol`

Without reading the actual source of these files, I cannot:

1. Trace the provider-change or fee-destination-change state transitions to confirm whether pending fees/LP claims are settled before the transition (the analog to "rewards sent before whitelist removal").
2. Verify whether `totalMultipliedStaked`-equivalent accounting (e.g., bin liquidity totals, fee accumulators) remains consistent after a provider swap or admin change.
3. Confirm or deny that existing guards already preserve the invariant.

Producing a finding or a clean rejection without reading the code would be fabrication. Due to index size limits, the contents of these files may not be available to the search tools in this session. To complete this analysis, start a Devin session with full filesystem access so the agent can read `MetricOmmPool.sol`, `MetricOmmPoolFactory.sol`, `MetricOmmPoolDeployer.sol`, and `PriceProviderFactory.sol` directly and trace the provider-change and fee-collection paths end-to-end.