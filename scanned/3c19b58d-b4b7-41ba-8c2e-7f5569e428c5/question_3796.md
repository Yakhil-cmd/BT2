# Q3796: EvmErc20V2.sol withdrawals pause assumption gap in interaction with refund-capable engine logic

## Question
Can a user reach interaction with refund-capable engine logic during a paused or partially paused engine state in a way that the token contract does not expect, causing value to be burned into a blocked path and leading to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `interaction with refund-capable engine logic`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: check how the token withdraw path behaves when its downstream engine route is not fully available.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Pause the relevant engine-side path and confirm the token withdraw function cannot burn value into an unrecoverable state. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
