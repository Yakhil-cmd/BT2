### Title
Incorrect Multi-NFT Royalty Arithmetic in WalletConnect Offer Confirmation Displays Understated Total to User — (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

`formatAmountWithRoyalties` in the Electron main-process WalletConnect confirmation path divides the payment amount by the number of NFTs before computing each royalty, producing a "Total Amount with Royalties" that is systematically understated by a factor of N (the number of royalty-bearing NFTs). The correct amount is shown in the `Confirm` dialog's "You Spend" section, so a user who relies on the royalty-inclusive total to decide whether to approve a `take_offer` or `create_offer_for_ids` WalletConnect request will approve while believing they are spending less than the blockchain will actually deduct.

---

### Finding Description

`formatAmountWithRoyalties` is called from `withRoyaltyTotals` → `walletDeltaToDisplay` → `parseCommandDisplay` for both `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids` WalletConnect commands. [1](#0-0) 

The arithmetic error is on line 363:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length); // ← divides by N
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

For N NFTs with royalty percentages `[r₁, r₂, …, rₙ]` and a payment of `amount` mojos:

| | Formula |
|---|---|
| **Displayed royalty** | `(amount / N) × Σrᵢ / 10 000` |
| **Correct royalty** | `amount × Σrᵢ / 10 000` |

The displayed royalty is exactly `1/N` of the correct value. For two NFTs the user sees half the actual royalty cost; for three NFTs, one-third; and so on.

The test suite encodes this wrong result as the expected value, confirming the bug is baked in: [2](#0-1) 

(amount = 100 000 000 mojos, royalties 500 + 10 → test expects `0.00010255` XCH; correct value is `0.0001051` XCH.)

The computed `amountWithRoyalties` string is attached to the `DisplayWalletDeltaItem` and rendered verbatim in the WalletConnect `Confirm` dialog under the label **"Total Amount with Royalties"**: [3](#0-2) 

The `Confirm` component is the sole approval gate the user sees before the signed transaction is submitted. [4](#0-3) 

---

### Impact Explanation

A user reviewing a WalletConnect `take_offer` or `create_offer_for_ids` request that involves N ≥ 2 royalty-bearing NFTs will see a "Total Amount with Royalties" that is `1/N` of the true cost. The user approves based on this understated figure; the actual blockchain spend is higher. This constitutes displaying the wrong amount in the WalletConnect signing approval flow, directly matching the **High** impact class: *"WalletConnect state that causes a user to approve … the wrong … amount."*

---

### Likelihood Explanation

Any dapp that has established a WalletConnect session can send a `take_offer` payload referencing a multi-NFT offer. No special privilege beyond a normal WalletConnect pairing is required. Multi-NFT offers with royalties are a standard Chia trading pattern, so the triggering condition is routine, not exotic.

---

### Recommendation

Remove the `splitAmount` division. Each NFT's royalty is independently applied to the full payment amount:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  // Each NFT royalty is applied to the full amount, not a per-NFT split.
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
  ...
}
```

Update the corresponding test expectations to reflect the corrected values.

---

### Proof of Concept

**Scenario:** A dapp sends a WalletConnect `chia_wallet.take_offer` for an offer where the user spends 1 XCH (1 000 000 000 000 mojos) to receive two NFTs — NFT-A with a 5 % royalty (500 basis points) and NFT-B with a 3 % royalty (300 basis points).

**Current (buggy) display:**

```
splitAmount = 1_000_000_000_000 / 2 = 500_000_000_000
royaltyA   = 500_000_000_000 × 500  / 10_000 = 25_000_000_000
royaltyB   = 500_000_000_000 × 300  / 10_000 = 15_000_000_000
total      = 1_000_000_000_000 + 40_000_000_000 = 1_040_000_000_000
→ Shown: "Total Amount with Royalties: 1.04 XCH"
```

**Correct value:**

```
royaltyA = 1_000_000_000_000 × 500 / 10_000 = 50_000_000_000
royaltyB = 1_000_000_000_000 × 300 / 10_000 = 30_000_000_000
total    = 1_000_000_000_000 + 80_000_000_000 = 1_080_000_000_000
→ Should show: "Total Amount with Royalties: 1.08 XCH"
```

The user approves believing they spend 1.04 XCH; the blockchain deducts 1.08 XCH — a 0.04 XCH discrepancy per transaction, scaling with royalty rates and number of NFTs. [5](#0-4) [3](#0-2) [6](#0-5)

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L354-375)
```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;

  if (line.kind === 'xch') {
    return mojoToChiaLocaleString(totalAmount);
  }

  return mojoToCATLocaleString(totalAmount);
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L377-394)
```typescript
function withRoyaltyTotals(
  items: DisplayWalletDeltaItemWithKey[],
  amounts: Record<string, bigint>,
  oppositeSideLines: DisplayWalletDeltaItem[],
): DisplayWalletDeltaItem[] {
  const royaltyPercentages = royaltyPercentagesForSide(oppositeSideLines);

  return items.map(({ key, line }) => {
    if (line.kind === 'nft') {
      return line;
    }

    const amount = amounts[key];
    const amountWithRoyalties = amount ? formatAmountWithRoyalties(line, amount, royaltyPercentages) : undefined;

    return amountWithRoyalties ? { ...line, amountWithRoyalties } : line;
  });
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L310-334)
```typescript
    await expect(
      parseCommandDisplay('chia_wallet.take_offer', {
        offer: 'offer1...',
      }),
    ).resolves.toMatchObject({
      walletDelta: {
        spending: [
          {
            kind: 'xch',
            amount: '0.0001',
            amountWithRoyalties: '0.00010255',
          },
        ],
        receiving: [
          {
            kind: 'nft',
            royaltyPercentage: 500,
          },
          {
            kind: 'nft',
            royaltyPercentage: 10,
          },
        ],
      },
    });
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L381-381)
```typescript
          {walletDelta && <WalletDeltaSection walletDelta={walletDelta} networkPrefix={networkPrefix} />}
```
