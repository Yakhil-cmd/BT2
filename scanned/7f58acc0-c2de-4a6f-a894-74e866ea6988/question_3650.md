# Q3650: EvmErc20.sol withdrawals external call shape mismatch in interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant

## Question
Can a user craft inputs through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` that make interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant build malformed but accepted ABI calldata for the exit contract, so the wrong recipient or amount is used and causes Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `interaction with the `EXIT_TO_ETHEREUM_ADDRESS` constant`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: target ABI encoding and downstream interpretation at the named withdraw function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Decode the produced calldata and compare every field to the public function arguments across fuzzed inputs. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
