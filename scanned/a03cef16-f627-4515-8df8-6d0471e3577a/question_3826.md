# Q3826: EvmErc20V2.sol withdrawals cross-exit mixup through total supply consistency after withdraw failures or reverts

## Question
Can a user route one withdrawal path through the assumptions of the other in total supply consistency after withdraw failures or reverts, so value meant for NEAR is sent to Ethereum semantics or vice versa, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `total supply consistency after withdraw failures or reverts`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: confuse exit path selection or parameters at the named function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Compare the calldata and target address for both withdrawal functions under edge-case inputs. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
