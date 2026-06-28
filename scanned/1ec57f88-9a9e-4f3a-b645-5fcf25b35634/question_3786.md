# Q3786: EvmErc20V2.sol withdrawals cross-exit mixup through interaction with refund-capable engine logic

## Question
Can a user route one withdrawal path through the assumptions of the other in interaction with refund-capable engine logic, so value meant for NEAR is sent to Ethereum semantics or vice versa, causing Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `interaction with refund-capable engine logic`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: confuse exit path selection or parameters at the named function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Compare the calldata and target address for both withdrawal functions under edge-case inputs. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
