### Title
MintManager `setMintingAllowance` Lacks Relative Adjustment Functions, Enabling Minting Allowance Double-Spend Frontrun - (File: `L1/starkware/solidity/stake/MintManager.sol`)

---

### Summary
`MintManager.setMintingAllowance` sets the minting allowance to an absolute value (identical to ERC20 `approve`). When the token admin reduces the allowance from `X` to `Y`, an attacker can front-run the transaction by triggering the L2 RewardSupplier to consume the old allowance `X` via `mintRequest`, then consume the new allowance `Y` after the change lands — minting `X + Y` tokens instead of the intended `Y`.

---

### Finding Description

`MintManager.sol` manages per-minter token minting allowances. The only way to change an existing allowance is `setMintingAllowance`, which overwrites the stored value unconditionally:

```solidity
function _setMintingAllowance(address token, address account, uint256 amount) private {
    mintingAllowance(token)[account] = amount;
    emit MintingAllowanceSet(token, account, amount);
}
```

This is the exact pattern that makes ERC20 `approve` vulnerable to the double-spend race condition. The protocol's own specification diagram acknowledges that `MintManager` should expose `increaseAllowance`, `decreaseAllowance`, `stopAllowance`, `approve`, and `allowance` — but the deployed contract only implements `setMintingAllowance` (absolute setter) and `cancelMintingAllowance` (zero setter). The safer relative-adjustment functions are absent from the implementation.

The registered minter for the STRK token is the L1 `RewardSupplier` contract. Its `tick()` function processes pending L2-to-L1 mint request messages and calls `mintRequest` on `MintManager`. L2-to-L1 messages in Starknet's messaging system are publicly consumable on L1 — anyone can call `tick()` to process them once they are finalized on L1.

An unprivileged staker on L2 can trigger the L2 `RewardSupplier` to emit mint request messages (via the staking reward claim flow). Combined with the ability to call `tick()` on L1, an attacker can time the consumption of the old allowance to front-run a `setMintingAllowance` reduction.

---

### Impact Explanation

**Impact: High — Theft of unclaimed yield / Protocol insolvency**

If the token admin reduces the minting allowance from `X` to `Y` (where `X > Y`):
- Attacker front-runs `setMintingAllowance` by calling `tick()` to consume allowance `X` via `mintRequest`
- `setMintingAllowance` lands, setting allowance to `Y`
- Attacker triggers more L2 mint requests and calls `tick()` again, consuming `Y`
- Total minted: `X + Y` instead of the intended `Y`

The extra `X` tokens are minted to the L2 `RewardSupplier` and distributed as staking rewards, constituting theft of unclaimed yield beyond the protocol's intended inflation schedule. The `PeriodMintLimit` cap of 6,500,000 tokens/week bounds the per-week damage but does not prevent the double-spend across the two allowance windows.

---

### Likelihood Explanation

**Likelihood: Low-Medium**

- The attack window only opens when the token admin actively reduces the minting allowance — not a routine operation, but it occurs during protocol parameter adjustments.
- The attacker must monitor the L1 mempool for `setMintingAllowance` transactions and have pending L2-to-L1 mint request messages ready to consume, or be able to generate them quickly from L2.
- L1 Ethereum mempool frontrunning is well-understood and routinely executed by MEV bots.
- No privileged access is required for the attacker — any staker can trigger L2 reward claims, and `tick()` is a public function.

---

### Recommendation

Replace `setMintingAllowance` with relative adjustment functions analogous to OpenZeppelin's `increaseAllowance` / `decreaseAllowance`, as already specified in the protocol's own architecture diagram:

```solidity
function increaseMintingAllowance(address token, address account, uint256 addedValue) external onlyTokenAdmin {
    require(registeredMinters(token)[account], "NOT_A_REGISTERED_MINTER");
    _setMintingAllowance(token, account, mintingAllowance(token)[account] + addedValue);
}

function decreaseMintingAllowance(address token, address account, uint256 subtractedValue) external onlyTokenAdmin {
    require(registeredMinters(token)[account], "NOT_A_REGISTERED_MINTER");
    uint256 current = mintingAllowance(token)[account];
    require(current >= subtractedValue, "DECREASED_BELOW_ZERO");
    _setMintingAllowance(token, account, current - subtractedValue);
}
```

If an absolute setter must be retained, it should first zero the allowance and require a separate transaction to set the new value (the two-step mitigation pattern).

---

### Proof of Concept

**Setup**: L2 RewardSupplier has a pending L2-to-L1 mint request message for `X` tokens. Token admin decides to reduce the minting allowance from `X` to `Y` and submits `setMintingAllowance(STRK, rewardSupplier, Y)` to L1.

**Attack**:
1. Attacker observes the pending `setMintingAllowance` transaction in the L1 mempool.
2. Attacker calls `RewardSupplier.tick()` on L1 with higher gas, front-running the admin tx. `tick()` calls `mintManager.mintRequest(STRK, X)`, consuming the full allowance `X`. `X` tokens are minted to the L2 RewardSupplier.
3. `setMintingAllowance(STRK, rewardSupplier, Y)` lands. Allowance is now `Y`.
4. Attacker triggers a new L2 reward claim from L2 (e.g., by calling `claim_rewards` on the staking contract), generating a new L2-to-L1 mint request for `Y` tokens.
5. After the message finalizes on L1, attacker calls `tick()` again. `mintRequest(STRK, Y)` succeeds. Another `Y` tokens are minted.

**Result**: `X + Y` tokens minted instead of `Y`. The excess `X` tokens are distributed as staking rewards, constituting theft of yield beyond the protocol's intended inflation.

**Relevant code**: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** L1/starkware/solidity/stake/MintManager.sol (L53-65)
```text
    function mintRequest(address token, uint256 amount) external {
        address requester = AccessControl._msgSender();
        require(registeredMinters(token)[requester], "NOT_A_REGISTERED_MINTER");
        require(mintingAllowance(token)[requester] >= amount, "INSUFFICIENT_MINTING_ALLOWANCE");

        // Update allowance.
        checkAndUpdatePeriodicalQuota(token, amount);
        mintingAllowance(token)[requester] -= amount;

        // Mint.
        mintableToken(token).mint(requester, amount);
        emit MintProcessed(token, requester, amount);
    }
```

**File:** L1/starkware/solidity/stake/MintManager.sol (L78-94)
```text
    function setMintingAllowance(
        address token,
        address account,
        uint256 amount
    ) external onlyTokenAdmin {
        require(registeredMinters(token)[account], "NOT_A_REGISTERED_MINTER");
        _setMintingAllowance(token, account, amount);
    }

    function _setMintingAllowance(
        address token,
        address account,
        uint256 amount
    ) private {
        mintingAllowance(token)[account] = amount;
        emit MintingAllowanceSet(token, account, amount);
    }
```

**File:** docs/spec.md (L444-451)
```markdown
  class MintManager {
    mintRequest()
    allowance()
    approve()
    increaseAllowance()
    decreaseAllowance()
    stopAllowance()
  }
```
