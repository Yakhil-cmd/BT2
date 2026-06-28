# Q3654: EvmErc20.sol withdrawals sandwiched failure around interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant

## Question
Can a user place one withdrawal before and one after a forced failure at interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant so the middle failure disturbs shared state and makes one of the successful calls mis-account value, causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: look for shared mutable state across withdrawal attempts.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Execute success-fail-success sequences and compare supply and user balances after every step. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
