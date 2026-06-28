# Q3788: EvmErc20V2.sol withdrawals event meaning split around interaction with refund-capable engine logic

## Question
Can a user make interaction with refund-capable engine logic emit or imply a successful withdrawal while the actual exit side effect differs, allowing downstream systems to act on false success and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `interaction with refund-capable engine logic`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: compare what the contract appears to signal with what the exit contract actually receives.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Capture events and external call payloads and confirm they always represent the same withdrawal result. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
