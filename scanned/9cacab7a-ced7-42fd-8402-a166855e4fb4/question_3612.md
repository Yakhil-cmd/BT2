# Q3612: EvmErc20.sol withdrawals zero-recipient edge in zero and extreme amount handling

## Question
Can a user pick a zero-like or empty recipient through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` so that zero and extreme amount handling accepts a withdrawal destination that later traps or misroutes value, causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `zero and extreme amount handling`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: probe empty and zero-like recipient representations at the named function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Test zero address, empty bytes, and short byte arrays and confirm they are rejected or routed safely. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
