# Q3588: EvmErc20.sol withdrawals event meaning split around recipient address routing in `withdrawToEthereum`

## Question
Can a user make recipient address routing in `withdrawToEthereum` emit or imply a successful withdrawal while the actual exit side effect differs, allowing downstream systems to act on false success and causing Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `recipient address routing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: compare what the contract appears to signal with what the exit contract actually receives.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Capture events and external call payloads and confirm they always represent the same withdrawal result. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
