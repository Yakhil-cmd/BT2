# Q3627: EvmErc20.sol withdrawals supply drift after interaction with the `EXIT_TO_NEAR_ADDRESS` constant

## Question
Can a user exercise interaction with the `EXIT_TO_NEAR_ADDRESS` constant so that ERC-20 total supply no longer matches the amount actually withdrawn or refunded on the engine side, eventually causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `interaction with the `EXIT_TO_NEAR_ADDRESS` constant`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: seek supply/accounting drift rooted at the targeted withdraw function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Track token supply and engine-side credited/debited value after crafted withdraw and failure sequences. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
