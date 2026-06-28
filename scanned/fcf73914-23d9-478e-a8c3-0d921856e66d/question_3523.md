# Q3523: EvmErc20.sol withdrawals amount boundary at burn-before-external-call sequencing in `withdrawToNear`

## Question
Can a user choose a zero, tiny, or extreme amount through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` that makes burn-before-external-call sequencing in `withdrawToNear` handle burn, exit, or supply accounting differently from the intended semantics and causes Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: attack numeric boundaries in the named withdrawal function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Fuzz around zero, one, full-balance, and near-overflow values and compare burn amount, exit amount, and remaining supply. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
