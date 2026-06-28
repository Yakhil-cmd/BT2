# Q3562: EvmErc20.sol withdrawals recipient encoding confusion in burn-before-external-call sequencing in `withdrawToEthereum`

## Question
Can a user supply recipient data through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` so that burn-before-external-call sequencing in `withdrawToEthereum` forwards a different recipient than the one visible in the public call, leading to Insolvency?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20.sol` -> `burn-before-external-call sequencing in `withdrawToEthereum``
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)`
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split the public recipient value from the forwarded exit recipient at the targeted function.
- Invariant to test: ERC-20 mirror withdrawals must burn the right balance once and route the exact intended amount to the exact intended exit path
- Expected Immunefi impact: Insolvency
- Fast validation: Call the function with crafted recipient values and inspect the exact ABI payload sent to the exit contract. write Solidity or integration tests that call both withdraw functions with crafted recipients and amounts, then inspect burn behavior, revert behavior, and exit side effects
