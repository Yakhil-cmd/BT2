# Q3687: EvmErc20V2.sol withdrawals supply drift after burn-before-external-call sequencing in `withdrawToNear`

## Question
Can a user exercise burn-before-external-call sequencing in `withdrawToNear` so that ERC-20 total supply no longer matches the amount actually withdrawn or refunded on the engine side, eventually causing Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `burn-before-external-call sequencing in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: seek supply/accounting drift rooted at the targeted withdraw function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Track token supply and engine-side credited/debited value after crafted withdraw and failure sequences. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
