# Q3677: EvmErc20.sol withdrawals token/engine desync around total supply consistency after withdraw failures or reverts

## Question
Can a user make total supply consistency after withdraw failures or reverts succeed at the token layer while the engine-side layer records a different asset movement or no movement at all, resulting in Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `total supply consistency after withdraw failures or reverts`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: target desynchronization between Solidity-side burn semantics and engine-side exit semantics.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Compare token-side state with engine-side exit side effects for every crafted withdraw branch. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
