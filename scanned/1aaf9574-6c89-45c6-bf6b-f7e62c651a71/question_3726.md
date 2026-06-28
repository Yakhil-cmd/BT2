# Q3726: EvmErc20V2.sol withdrawals cross-exit mixup through burn-before-external-call sequencing in `withdrawToEthereum`

## Question
Can a user route one withdrawal path through the assumptions of the other in burn-before-external-call sequencing in `withdrawToEthereum`, so value meant for NEAR is sent to Ethereum semantics or vice versa, causing Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `burn-before-external-call sequencing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: confuse exit path selection or parameters at the named function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Insolvency
- Fast validation: Compare the calldata and target address for both withdrawal functions under edge-case inputs. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
