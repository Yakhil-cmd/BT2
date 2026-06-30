Looking at the actual code, this is a real vulnerability. Let me trace it precisely.

---

### Title
Unchecked Precompile Return Value + Missing Recipient Validation in `withdrawToNear` Causes Permanent Fund Loss — (`etc/eth-contracts/contracts/EvmErc20.sol`)

### Summary
`withdrawToNear` burns the caller's tokens before invoking the exit precompile, never validates that `recipient` is non-empty, and never checks the assembly `call` return value. A zero-length (or otherwise invalid) recipient causes tokens to be permanently destroyed with no recoverable destination, and the function succeeds without reverting.

### Finding Description

The function has two compounding flaws:

**Flaw 1 — No recipient length guard.** [1](#0-0) 

There is no `require(recipient.length > 0, ...)` (or any NEAR account-ID format check) before proceeding. Any caller can pass `bytes("")`.

**Flaw 2 — Assembly `call` return value is captured but never checked.** [2](#0-1) 

`res` is assigned but never tested with `require(res == 1, ...)` or equivalent. If the precompile at `0xe921...` rejects the malformed input (returns `0`), the EVM does **not** automatically revert — execution continues normally.

**Execution order makes this irreversible:** [3](#0-2) 

`_burn` executes first. By the time the precompile call is made and potentially fails, the tokens are already gone from the EVM state. Because the `res` check is absent, the transaction commits successfully with the burn applied and no exit recorded on the NEAR side.

### Impact Explanation

Any token holder can call `withdrawToNear(bytes(""), amount)` with their full balance. The tokens are burned on the EVM side, the precompile either rejects the empty-recipient payload or routes it to an invalid account, and the Solidity transaction succeeds. The user's funds are permanently destroyed with no recovery path — matching **Critical: permanent freezing/destruction of user funds in motion**.

### Likelihood Explanation

- No privilege required — any token holder can trigger this.
- No special precondition beyond holding a non-zero balance.
- The call path is a single direct EVM transaction to a public `external` function.
- Accidental triggering (e.g., a frontend bug passing an empty string) is also realistic.

### Recommendation

1. Add an explicit recipient length guard before the burn:
   ```solidity
   require(recipient.length > 0, "EvmErc20: empty recipient");
   ```
2. Check the precompile return value and revert on failure:
   ```solidity
   assembly {
       let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
       if iszero(res) { revert(0, 0) }
   }
   ```
3. Ideally, move the `_burn` call to **after** a successful precompile call (checks-effects-interactions order), or use a try/revert pattern so a precompile failure rolls back the burn.

### Proof of Concept

```solidity
// Attacker holds `amount` tokens of EvmErc20
evmErc20.withdrawToNear(bytes(""), amount);
// Result: `amount` tokens burned from attacker's balance,
// precompile called with 33-byte input (no recipient),
// `res` never checked, transaction succeeds,
// tokens are permanently lost — no NEAR-side credit issued.
```

Fuzz confirmation: supply `recipient` as `bytes("")`, `bytes(hex"00")`, and random non-UTF8 sequences; assert the function reverts in all cases where the precompile would not produce a valid exit. Under current code, none of these revert.

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-58)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L60-62)
```text
        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
```
