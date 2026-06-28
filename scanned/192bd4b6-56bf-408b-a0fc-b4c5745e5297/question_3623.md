# Q3623: EvmErc20.sol withdrawals amount boundary at interaction with the `EXIT_TO_NEAR_ADDRESS` constant

## Question
Can a user choose a zero, tiny, or extreme amount through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` that makes interaction with the `EXIT_TO_NEAR_ADDRESS` constant handle burn, exit, or supply accounting differently from the intended semantics and causes Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `interaction with the `EXIT_TO_NEAR_ADDRESS` constant`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: attack numeric boundaries in the named withdrawal function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Fuzz around zero, one, full-balance, and near-overflow values and compare burn amount, exit amount, and remaining supply. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
