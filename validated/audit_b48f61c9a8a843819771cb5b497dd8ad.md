### Title
`tick()` Can Exhaust the Weekly `PERIOD_MINT_CAP` in a Single Call, Blocking Subsequent Reward Minting Until the Next Period - (File: `L1/starkware/solidity/stake/RewardSupplier.sol`, `L1/starkware/solidity/stake/PeriodMintLimit.sol`)

---

### Summary

The L1 `RewardSupplier.tick()` function processes up to `MAX_MESSAGES_TO_PROCESS_PER_TICK = 5` L2→L1 mint-request messages per call, minting `5 × TOKENS_PER_MINT_REQUEST = 5 × 1,300,000 × 10^18 = 6,500,000 × 10^18` tokens — which is **exactly** the `PERIOD_MINT_CAP`. Because `tick()` is permissionless and always attempts to mint the full `numMsgsToConsume × TOKENS_PER_MINT_REQUEST` amount with no partial-batch fallback, a caller who invokes `tick()` early in a period (when only 1–4 messages are pending) partially consumes the weekly cap. When the L2 `request_funds` subsequently sends a fresh batch of 5 messages, the next `tick()` call reverts with `"EXCEED_PERIOD_MINTING"` for the remainder of the week, freezing reward delivery to L2.

---

### Finding Description

**`PeriodMintLimit.sol`** enforces a hard weekly cap:

```
PERIOD_MINT_CAP        = 6_500_000 × 10^18
MINTING_PERIOD_DURATION = 1 week
```

`checkAndUpdatePeriodicalQuota` accumulates all minting within the current period slot and reverts if the total would exceed the cap. [1](#0-0) 

**`RewardSupplier.sol`** defines:

```
TOKENS_PER_MINT_REQUEST        = 1_300_000 × 10^18
MAX_MESSAGES_TO_PROCESS_PER_TICK = 5
```

One fully-loaded `tick()` call mints `5 × 1,300,000 × 10^18 = PERIOD_MINT_CAP` — the cap is sized to exactly one maximum tick. [2](#0-1) 

`tick()` is permissionless (`external payable`, no role check) and always attempts to mint the full `numMsgsToConsume × TOKENS_PER_MINT_REQUEST`: [3](#0-2)

### Citations

**File:** L1/starkware/solidity/stake/PeriodMintLimit.sol (L18-24)
```text
    function checkAndUpdatePeriodicalQuota(address token, uint256 amount) internal {
        bytes32 periodSlot = periodAccountingSlot(token);
        uint256 mintedThisPeriodBefore = periodMintAccounting()[periodSlot];
        uint256 mintedThisPeriodAfter = mintedThisPeriodBefore + amount;
        require(mintedThisPeriodAfter <= PERIOD_MINT_CAP, "EXCEED_PERIOD_MINTING");
        periodMintAccounting()[periodSlot] = mintedThisPeriodAfter;
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L10-11)
```text
uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;
uint256 constant MAX_MESSAGES_TO_PROCESS_PER_TICK = 5;
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-122)
```text
    function tick() external payable {
        // Check if minting is required, and how much.
        (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

        if (amountToMint > 0) {
            // Prepare the L2->L1 mintRequest message for consumption.
            uint256[] memory messagePayload = new uint256[](1);
            messagePayload[0] = TOKENS_PER_MINT_REQUEST;

            // Consume the mintRequest messages.
            for (uint256 i = 0; i < numMsgsToConsume; i++) {
                messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload);
            }

            // Reuest minting of the requested amount from the mint manager.
            mintManager().mintRequest(token(), amountToMint);
```
