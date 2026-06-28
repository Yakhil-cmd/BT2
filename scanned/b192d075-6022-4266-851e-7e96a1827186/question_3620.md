# Q3620: EvmErc20.sol withdrawals wrong-asset recovery path after zero and extreme amount handling

## Question
Can a user make zero and extreme amount handling fall into a recovery or refund path that restores the wrong asset or wrong amount, leaving the intended asset short and causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `zero and extreme amount handling`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split the main withdrawal asset from the asset used to compensate failure around the named function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Inject failing exit conditions and verify any recovery path restores the exact same asset and amount that was burned. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
