# Q3639: EvmErc20.sol withdrawals shared liquidity drain seeded by interaction with the `EXIT_TO_NEAR_ADDRESS` constant

## Question
Can a user repeatedly invoke interaction with the `EXIT_TO_NEAR_ADDRESS` constant so a small per-call mismatch accumulates into a drain on shared mirrored liquidity or backing balances, causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `interaction with the `EXIT_TO_NEAR_ADDRESS` constant`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: amplify a small supply/backing mismatch rooted in the targeted withdraw function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Run a high-count local sequence and compare cumulative user withdrawals against cumulative backing movement. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
