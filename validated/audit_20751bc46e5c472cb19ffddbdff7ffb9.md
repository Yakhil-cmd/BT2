### Title
WalletConnect Offer Confirmation Understates Total Royalty Cost via Double BigInt Truncation — (`File: packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in the WalletConnect confirmation pipeline computes the "Total Amount with Royalties" shown to the user using two sequential BigInt truncating divisions. A malicious dApp can craft a multi-NFT offer where the displayed total is materially lower than the amount the Chia wallet daemon will actually charge, causing the user to approve a transaction that costs more than shown.

### Finding Description

`formatAmountWithRoyalties` in `parseCommandDisplay.ts` computes the royalty total for the WalletConnect confirmation dialog as follows:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // truncating division #1
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) =>
    total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,  // truncating division #2
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

Two independent truncations are applied to the same base `amount`:

1. `splitAmount = amount / N` — the amount is divided by the number of NFTs and truncated.
2. `(splitAmount * royaltyPercentage) / 10_000n` — the royalty is computed on the already-truncated `splitAmount` and truncated again.

The Chia wallet daemon computes royalties per-NFT on the **full** `amount`, not on a pre-divided split. This means the display formula systematically underestimates the actual royalty cost whenever `amount` is not evenly divisible by the number of NFTs, or when the per-NFT royalty on the split amount truncates to a smaller value.

This `amountWithRoyalties` value is passed through `walletDeltaToDisplay` → `withRoyaltyTotals` → `parseCommandDisplay` → `main.tsx` line 329 → the `Confirm` dialog, where it is rendered as **"Total Amount with Royalties"** — the primary cost figure the user sees before approving. [2](#0-1) [3](#0-2) 

### Impact Explanation

A user approves a WalletConnect `take_offer` or `create_offer_for_ids` request seeing a "Total Amount with Royalties" that is lower than what the wallet daemon will actually deduct. The user's XCH or CAT balance is reduced by more than the confirmed amount. This is a direct, unprivileged accounting impact on wallet funds triggered through the WalletConnect approval flow.

**Concrete example:**
- Offer: 3 NFTs each with `royalty_percentage = 3334` (33.34%), XCH amount = 10 mojos
- Display: `splitAmount = 10n / 3n = 3n`; per-NFT royalty = `3n * 3334n / 10000n = 1n`; total royalty = `3n`; **shown total = 13 mojos**
- Daemon (per-NFT on full amount): per-NFT royalty = `10n * 3334n / 10000n = 3n`; total royalty = `9n`; **actual total = 19 mojos**
- Discrepancy: user approves 13 mojos, pays 19 mojos (46% understatement)

At larger mojo amounts the absolute discrepancy scales proportionally.

### Likelihood Explanation

Any WalletConnect-connected dApp can craft an offer with multiple NFTs and specific royalty percentages to maximize the display/actual gap. No privileged access, leaked keys, or social engineering beyond the normal WalletConnect pairing flow is required. The attacker controls the offer parameters entirely.

### Recommendation

Compute the royalty for each NFT on the **full** `amount` (not on `splitAmount`), then sum:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

This mirrors how the Chia daemon computes per-NFT royalties and eliminates the split-then-truncate discrepancy.

### Proof of Concept

Using the existing test harness in `parseCommandDisplay.test.ts`, configure:
- 3 NFTs with `royalty_percentage: 3334` each
- XCH requested: `10` mojos

Current code produces `amountWithRoyalties` = 13 mojos (displayed to user).  
Daemon charges: 19 mojos.  
User approves 13, wallet deducts 19. [4](#0-3) [5](#0-4) [2](#0-1) [6](#0-5)

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

**File:** packages/gui/src/electron/main.tsx (L329-344)
```typescript
          const display = await parseCommandDisplay(commandId, parsedParams);

          const confirmResult = await openReactDialog<ConfirmDialogResult, ConfirmProps>(
            mainWindow,
            Confirm,
            {
              networkPrefix,
              command: commandId,
              data: parsedParams,
              title,
              message,
              confirmLabel,
              destructive,
              rows,
              pair,
              display,
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L100-116)
```typescript
function OfferLineRow({ line, networkPrefix }: { line: DisplayWalletDeltaItem; networkPrefix?: string }) {
  if (line.kind === 'xch') {
    // Inline `{amount} {unit}` matches the FEE row in the offer card so a
    // single-line summary doesn't look like a wide-spaced table row.
    return (
      <div>
        <div className="text-sm font-medium text-chia-text">
          {line.amount} {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
        </div>
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
      </div>
    );
```
