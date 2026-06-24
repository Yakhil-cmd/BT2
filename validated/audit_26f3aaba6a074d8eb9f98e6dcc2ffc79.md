Audit Report

## Title
Fee-on-Transfer ERC-20 Token Causes ckERC20 Over-Minting (Chain-Fusion Ledger Conservation Bug) - (File: `rs/ethereum/cketh/minter/DepositHelperWithSubaccount.sol`, `rs/ethereum/cketh/minter/ERC20DepositHelper.sol`, `rs/ethereum/cketh/minter/src/deposit.rs`)

## Summary
Both ckERC20 deposit helper contracts emit a deposit event carrying the caller-supplied `amount` without verifying the actual tokens received by the minter address. The IC minter canister scrapes these events and mints exactly `event.value()` ckERC20 tokens. For any fee-on-transfer ERC-20 token, the minter receives `amount - fee` on Ethereum while minting `amount` on the IC ledger, permanently breaking the 1:1 backing invariant and causing protocol insolvency.

## Finding Description
In `DepositHelperWithSubaccount.sol`, `depositErc20` calls `safeTransferFrom(msg.sender, minterAddress, amount)` and unconditionally emits `ReceivedEthOrErc20(..., amount, ...)` using the caller-supplied value with no balance-before/balance-after check:

```solidity
// DepositHelperWithSubaccount.sol lines 519-531
erc20Token.safeTransferFrom(msg.sender, minterAddress, amount);
emit ReceivedEthOrErc20(erc20Address, msg.sender, amount, principal, subaccount);
```

The identical pattern exists in `ERC20DepositHelper.sol` `CkErc20Deposit.deposit` at lines 498-503:

```solidity
erc20Token.safeTransferFrom(msg.sender, cketh_minter_main_address, amount);
emit ReceivedErc20(erc20_address, msg.sender, amount, principal);
```

Although `IERC20.balanceOf` is available in the interface (defined at line 291 of `ERC20DepositHelper.sol`), neither deposit function calls it. There is no mechanism to detect the actual received amount.

On the IC side, `deposit.rs` `mint()` reads the scraped event and calls `ICRC1Client.transfer` with `amount: event.value()` verbatim (lines 73-81), where `event.value()` is populated directly from the `ReceivedErc20Event.value: Erc20Value` field (parsed from the Ethereum log, `eth_logs/mod.rs` lines 57-75). No cross-check against the minter's actual on-chain ERC-20 balance is performed at any point in the pipeline.

For a fee-on-transfer token charging fee `f` on every `transferFrom`, a deposit of `amount` results in the minter holding `amount - f` ERC-20 tokens while the IC ledger mints `amount` ckERC20 tokens. The discrepancy accumulates with every deposit.

## Impact Explanation
This constitutes **illegal minting** and **protocol insolvency** for any NNS-approved fee-on-transfer ERC-20 token. The ckERC20 total supply on the IC ledger permanently exceeds the ERC-20 balance held by the minter's Ethereum address, breaking the 1:1 backing invariant that is the foundational security property of the ckERC20 system. Once the minter's ERC-20 balance is exhausted by withdrawal requests, remaining ckERC20 holders cannot redeem their tokens. This matches the Critical impact category: *"Theft, permanent loss, illegal minting, or protocol insolvency involving exorbitant ICP/Cycles or in-scope chain-key/ledger assets."* USDT — already an approved ckERC20 token — has a dormant fee mechanism that its owner can activate at any time, making this a concrete near-term risk rather than a purely hypothetical one.

## Likelihood Explanation
The precondition is that a fee-on-transfer ERC-20 token is NNS-approved. This is not a governance attack; it is the normal token-addition process. USDT (`0xdAC17F958D2ee523a2206206994597C13D831ec7`) is already in the supported token list and contains a fee mechanism currently set to zero but activatable by its owner. Any future NNS proposal adding a token with an active transfer fee would trigger the bug immediately. Once the precondition is met, exploitation requires no privilege: any Ethereum user can call `depositErc20` on the helper contract. The attack is repeatable, permissionless, and requires no victim interaction.

## Recommendation
In both `depositErc20` (`DepositHelperWithSubaccount.sol`) and `deposit` (`ERC20DepositHelper.sol`), record the minter's ERC-20 balance before and after `safeTransferFrom` and emit the actual received amount (the difference) rather than the caller-supplied `amount`:

```solidity
uint256 balanceBefore = erc20Token.balanceOf(minterAddress);
erc20Token.safeTransferFrom(msg.sender, minterAddress, amount);
uint256 actualReceived = erc20Token.balanceOf(minterAddress) - balanceBefore;
require(actualReceived > 0, "ERC20: zero amount received");
emit ReceivedEthOrErc20(erc20Address, msg.sender, actualReceived, principal, subaccount);
```

This ensures the IC minter mints only what was actually received, preserving the 1:1 backing invariant regardless of the underlying token's fee behavior.

## Proof of Concept
1. USDT owner activates the USDT transfer fee (or any new fee-on-transfer token is NNS-approved).
2. Alice calls `depositErc20(usdtAddress, 1000e6, alicePrincipal, 0x)` on the `CkDeposit` helper contract.
3. USDT deducts its fee on `transferFrom`: minter receives `990e6`, but the helper emits `ReceivedEthOrErc20(..., 1000e6, ...)`.
4. The IC minter scrapes the log, reads `value = 1000e6` from `ReceivedErc20Event`, and calls `ICRC1Client.transfer(amount: 1000e6)` on the ckUSDT ledger.
5. Alice receives `1000e6` ckUSDT but the minter holds only `990e6` USDT.
6. After 100 such deposits, the minter holds `99_000e6` USDT while ckUSDT total supply is `100_000e6`.
7. The last ~1% of ckUSDT holders cannot redeem; withdrawal transactions fail due to insufficient USDT balance at the minter address.

A deterministic integration test can be written using the existing `CkErc20Setup` test harness in `rs/ethereum/cketh/minter/tests/ckerc20.rs` by deploying a mock ERC-20 token that deducts a fee in `transferFrom`, injecting a `ReceivedErc20` log entry with the pre-fee amount, and asserting that the ckERC20 total supply exceeds the mock token balance held by the minter address.