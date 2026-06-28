# Q3777: EvmErc20V2.sol withdrawals token/engine desync around zero and extreme amount handling

## Question
Can a user make zero and extreme amount handling succeed at the token layer while the engine-side layer records a different asset movement or no movement at all, resulting in Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `zero and extreme amount handling`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: target desynchronization between Solidity-side burn semantics and engine-side exit semantics.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Compare token-side state with engine-side exit side effects for every crafted withdraw branch. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
