# Q3782: EvmErc20V2.sol withdrawals recipient encoding confusion in interaction with refund-capable engine logic

## Question
Can a user supply recipient data through a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract so that interaction with refund-capable engine logic forwards a different recipient than the one visible in the public call, leading to Temporary freezing of funds?

## Target
- File/function: `etc/eth-contracts/contracts/EvmErc20V2.sol` -> `interaction with refund-capable engine logic`
- Entrypoint: a user-held mirrored ERC-20 token calling `withdrawToNear(bytes,uint256)` or `withdrawToEthereum(address,uint256)` on the V2 contract
- Attacker controls: ERC-20 token balance, recipient bytes or address, withdraw amount, approval state, and repeated withdraw timing
- Exploit idea: split the public recipient value from the forwarded exit recipient at the targeted function.
- Invariant to test: the V2 mirror contract must preserve one-burn-one-exit semantics even on the refund-capable path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Call the function with crafted recipient values and inspect the exact ABI payload sent to the exit contract. write Solidity or integration tests that target the V2 withdraw paths and compare supply, revert handling, and exit-side behavior with the base contract
