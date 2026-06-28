# Q3594: EvmErc20.sol withdrawals sandwiched failure around recipient address routing in `withdrawToEthereum`

## Question
Can a user place one withdrawal before and one after a forced failure at recipient address routing in `withdrawToEthereum` so the middle failure disturbs shared state and makes one of the successful calls mis-account value, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `recipient address routing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: look for shared mutable state across withdrawal attempts.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Execute success-fail-success sequences and compare supply and user balances after every step. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
