# Q3529: EvmErc20.sol withdrawals address-constant assumption at burn-before-external-call sequencing in `withdrawToNear`

## Question
Can a user exploit the fixed exit-address assumption used by burn-before-external-call sequencing in `withdrawToNear` so that a deployment, mirror, or surrounding engine condition breaks the intended route and leads to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: stress the assumption that the hard-coded exit address always represents the intended target behavior.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Test against realistic deployment and mirror contexts and verify the hard-coded address still refers to the expected behavior only. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
