# Q3710: EvmErc20V2.sol withdrawals external call shape mismatch in recipient byte encoding in `withdrawToNear`

## Question
Can a user craft inputs through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract that make recipient byte encoding in `withdrawToNear` build malformed but accepted ABI calldata for the exit contract, so the wrong recipient or amount is used and causes Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `recipient byte encoding in `withdrawToNear``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: target ABI encoding and downstream interpretation at the named withdraw function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Decode the produced calldata and compare every field to the public function arguments across fuzzed inputs. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
