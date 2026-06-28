# Q3605: EvmErc20.sol withdrawals revert/success split at zero and extreme amount handling

## Question
Can a user make zero and extreme amount handling treat a failed external exit as if the withdrawal succeeded, or vice versa, leaving token supply and bridged value out of sync and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `zero and extreme amount handling`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split external-call result handling from supply semantics at the targeted function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Inject failing exit targets in tests and assert supply and user balances always match the real external outcome. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
