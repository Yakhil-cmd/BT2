### Title
WalletConnect Offer Confirmation Displays Understated Royalty Total for Multi-NFT Offers — (`File: packages/gui/src/electron/commands/parseCommandDisplay.ts`)

---

### Summary

The `formatAmountWithRoyalties` function in the WalletConnect confirmation pipeline incorrectly divides the fungible amount by the number of NFTs before computing each NFT's royalty contribution. When a dApp sends a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` command containing multiple royalty-bearing NFTs, the "Total Amount with Royalties" shown to the user in the approval dialog is understated by a factor of N (the number of NFTs). A malicious dApp can exploit this to make the user approve a spend that is significantly larger than what the confirmation screen displays.

---

### Finding Description

In `parseCommandDisplay.ts`, `formatAmountWithRoyalties` computes the displayed royalty total as follows:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by N
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

`splitAmount` is `amount / N`. Each NFT's royalty is then `(amount / N) * royaltyPct / 10_000`. Summed over N NFTs, the total royalty displayed is:

```
displayed_royalty = (amount / N) * Σ(royaltyPct_i) / 10_000
```

The mathematically correct total royalty is:

```
correct_royalty = amount * Σ(royaltyPct_i) / 10_000
```

The displayed value is exactly `1/N` of the correct value. The `splitAmount` division is the root cause — it was presumably intended to split the XCH evenly across NFTs for some purpose, but royalties are each applied to the **full** fungible amount, not a fraction of it.

The result is passed to `withRoyaltyTotals` and ultimately rendered in the WalletConnect confirmation dialog (`Confirm.tsx`) as "Total Amount with Royalties":

```tsx
{line.amountWithRoyalties && (
  <div className="text-xs text-chia-text-secondary">
    {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties} ...
  </div>
)}
``` [2](#0-1) 

The existing test suite confirms the buggy value as the expected output:

```
// 2 NFTs: royalty_percentage 500 + 10, XCH 100000000 mojos
amountWithRoyalties: '0.00010255'   // test expects this (wrong)
// correct value: 0.0001051
``` [3](#0-2) 

---

### Impact Explanation

The WalletConnect confirmation dialog is the sole security gate between a dApp's request and the user's wallet. When a dApp sends `chia_wallet.take_offer` with an offer containing N royalty-bearing NFTs, the dialog shows a "Total Amount with Royalties" that is `1/N` of the correct royalty burden. The user approves believing they will spend `amount + royalty/N`, but the blockchain deducts `amount + royalty`. The discrepancy grows with both the number of NFTs and the royalty percentages.

**Concrete example — 10 NFTs each with 10% royalty, base price 10 XCH:**
- Displayed total: 10 + 0.1 = **10.1 XCH**
- Actual deduction: 10 + 10×1 = **20 XCH**

This matches the allowed High impact: *"WalletConnect state that causes a user to approve… the wrong… amount."*

---

### Likelihood Explanation

Any WalletConnect-connected dApp can craft and submit a `chia_wallet.take_offer` payload with multiple NFTs. No special privilege is required. The user has no other signal in the confirmation UI to detect the understatement; the base `amount` field is correct, but the "Total Amount with Royalties" line — the only field that accounts for royalties — is wrong. The bug is triggered automatically whenever N ≥ 2. [4](#0-3) 

---

### Recommendation

Remove the `/ BigInt(royaltyPercentages.length)` division. Each NFT's royalty is applied to the full fungible amount:

```typescript
// Before (incorrect):
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);

// After (correct):
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test expectations in `parseCommandDisplay.test.ts` to reflect the correct values. [5](#0-4) 

---

### Proof of Concept

1. Attacker dApp connects via WalletConnect.
2. Attacker creates an offer: sell 2 NFTs (each with `royalty_percentage = 1000`, i.e. 10%) in exchange for 10 XCH.
3. Attacker sends `chia_wallet.take_offer` to the victim's GUI.
4. `parseCommandDisplay` calls `formatAmountWithRoyalties` with `amount = 10_000_000_000_000n` (10 XCH in mojos) and `royaltyPercentages = [1000, 1000]`.
5. `splitAmount = 10_000_000_000_000n / 2n = 5_000_000_000_000n`
6. `royaltyAmount = (5_000_000_000_000n * 1000n / 10_000n) + (5_000_000_000_000n * 1000n / 10_000n) = 500_000_000_000n + 500_000_000_000n = 1_000_000_000_000n`
7. Displayed total: `11_000_000_000_000n` → **11 XCH**
8. Correct total: `10_000_000_000_000n + 2 × 1_000_000_000_000n = 12_000_000_000_000n` → **12 XCH**
9. User sees "Total Amount with Royalties: 11 XCH" and approves; blockchain deducts **12 XCH**. [6](#0-5)

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L438-459)
```typescript
export async function parseCommandDisplay(command: string, params: Record<string, unknown>) {
  if (command === 'chia_wallet.take_offer') {
    if (!params.offer || typeof params.offer !== 'string') {
      throw new Error('Offer is not valid');
    }

    const offerSummary = await getOfferSummary(params.offer);
    if (!offerSummary || !offerSummary.summary || !offerSummary.success) {
      throw new Error('Offer is not valid');
    }

    const { summary } = offerSummary;

    const walletDelta = offerSummaryToWalletDelta(summary);
    const walletInfos = await getWalletInfos();
    const assetKinds = offerSummaryAssetKinds(summary);
    const royaltyPercentages = offerSummaryRoyaltyPercentages(summary);
    const fees = parseMojos(summary.fees);

    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, fees),
    };
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-115)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
      </div>
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
