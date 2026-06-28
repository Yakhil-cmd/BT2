# Q3560: EvmErc20.sol withdrawals wrong-asset recovery path after recipient byte encoding in `withdrawToNear`

## Question
Can a user make recipient byte encoding in `withdrawToNear` fall into a recovery or refund path that restores the wrong asset or wrong amount, leaving the intended asset short and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `recipient byte encoding in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split the main withdrawal asset from the asset used to compensate failure around the named function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Inject failing exit conditions and verify any recovery path restores the exact same asset and amount that was burned. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
