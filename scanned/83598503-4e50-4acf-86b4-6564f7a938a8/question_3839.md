# Q3839: EvmErc20V2.sol withdrawals shared liquidity drain seeded by total supply consistency after withdraw failures or reverts

## Question
Can a user repeatedly invoke total supply consistency after withdraw failures or reverts so a small per-call mismatch accumulates into a drain on shared mirrored liquidity or backing balances, causing Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `total supply consistency after withdraw failures or reverts`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: amplify a small supply/backing mismatch rooted in the targeted withdraw function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Run a high-count local sequence and compare cumulative user withdrawals against cumulative backing movement. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
