# Q3526: EvmErc20.sol withdrawals cross-exit mixup through burn-before-external-call sequencing in `withdrawToNear`

## Question
Can a user route one withdrawal path through the assumptions of the other in burn-before-external-call sequencing in `withdrawToNear`, so value meant for NEAR is sent to Ethereum semantics or vice versa, causing Permanent freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: confuse exit path selection or parameters at the named function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Compare the calldata and target address for both withdrawal functions under edge-case inputs. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
