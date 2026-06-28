# Q3783: EvmErc20V2.sol withdrawals amount boundary at interaction with refund-capable engine logic

## Question
Can a user choose a zero, tiny, or extreme amount through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract that makes interaction with refund-capable engine logic handle burn, exit, or supply accounting differently from the intended semantics and causes Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `interaction with refund-capable engine logic`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: attack numeric boundaries in the named withdrawal function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Insolvency
- Fast validation: Fuzz around zero, one, full-balance, and near-overflow values and compare burn amount, exit amount, and remaining supply. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
