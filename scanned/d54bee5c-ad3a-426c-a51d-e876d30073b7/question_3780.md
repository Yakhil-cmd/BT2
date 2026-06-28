# Q3780: EvmErc20V2.sol withdrawals wrong-asset recovery path after zero and extreme amount handling

## Question
Can a user make zero and extreme amount handling fall into a recovery or refund path that restores the wrong asset or wrong amount, leaving the intended asset short and causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `zero and extreme amount handling`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split the main withdrawal asset from the asset used to compensate failure around the named function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Insolvency
- Fast validation: Inject failing exit conditions and verify any recovery path restores the exact same asset and amount that was burned. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
