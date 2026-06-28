# Q3645: EvmErc20.sol withdrawals revert/success split at interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant

## Question
Can a user make interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant treat a failed external exit as if the withdrawal succeeded, or vice versa, leaving token supply and bridged value out of sync and causing Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split external-call result handling from supply semantics at the targeted function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Inject failing exit targets in tests and assert supply and user balances always match the real external outcome. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
