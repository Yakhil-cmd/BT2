# Q3749: EvmErc20V2.sol withdrawals address-constant assumption at recipient address routing in `withdrawToEthereum`

## Question
Can a user exploit the fixed exit-address assumption used by recipient address routing in `withdrawToEthereum` so that a deployment, mirror, or surrounding engine condition breaks the intended route and leads to Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `recipient address routing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: stress the assumption that the hard-coded exit address always represents the intended target behavior.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Insolvency
- Fast validation: Test against realistic deployment and mirror contexts and verify the hard-coded address still refers to the expected behavior only. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
