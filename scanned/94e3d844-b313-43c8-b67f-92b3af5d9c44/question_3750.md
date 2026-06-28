# Q3750: EvmErc20V2.sol withdrawals external call shape mismatch in recipient address routing in `withdrawToEthereum`

## Question
Can a user craft inputs through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract that make recipient address routing in `withdrawToEthereum` build malformed but accepted ABI calldata for the exit contract, so the wrong recipient or amount is used and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `recipient address routing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: target ABI encoding and downstream interpretation at the named withdraw function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Decode the produced calldata and compare every field to the public function arguments across fuzzed inputs. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
