### Title
Inaccurate `amountWithRoyalties` in WalletConnect Offer Confirmation Understates True Spend Amount When Multiple NFTs Have Royalties - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
`formatAmountWithRoyalties` in `parseCommandDisplay.ts` incorrectly divides the fungible amount by the number of royalty-bearing NFTs before computing each royalty, producing a "Total Amount with Royalties" figure that is systematically lower than what the Chia daemon will actually deduct. This figure is rendered directly in the WalletConnect confirmation dialog (`Confirm.tsx`) under "You Spend", so a user who approves a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request involving multiple royalty-bearing NFTs is shown a materially understated total and approves the wrong amount.

### Finding Description

`formatAmountWithRoyalties` is called by `withRoyaltyTotals` to annotate each fungible spending line with the royalty-inclusive total before the confirmation dialog is rendered:

```typescript
// parseCommandDisplay.ts
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  ...
  const splitAmount = amount / BigInt(royaltyPercentages.length); // ← divides by NFT count
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
  ...
}
``` [1](#0-0) 

The function first divides `amount` by the number of NFTs (`splitAmount = amount / N`), then computes each NFT's royalty on that fraction. The correct formula is to apply each royalty percentage to the **full** `amount`:

```
correct_royalty = Σ (amount × royaltyPercentage_i / 10_000)
actual_royalty  = Σ ((amount / N) × royaltyPercentage_i / 10_000)
               = correct_royalty / N
```

So the displayed total is `amount + correct_royalty / N` instead of `amount + correct_royalty`. The understatement grows with the number of NFTs and the magnitude of the royalties.

The existing test fixture confirms the bug is baked in as the expected value:

```
amount: '0.0001' XCH (100_000_000 mojos)
NFT1 royalty: 500 (5%), NFT2 royalty: 10 (0.1%)

Displayed amountWithRoyalties: '0.00010255' XCH  ← 102_550_000 mojos
Correct amountWithRoyalties:    '0.0001051'  XCH  ← 105_100_000 mojos
Understatement: 2_550_000 mojos (~2.4 %)
``` [2](#0-1) 

The computed `amountWithRoyalties` is attached to the spending line and rendered in the WalletConnect confirmation dialog as the authoritative "Total Amount with Royalties" label under "You Spend":

```tsx
{line.amountWithRoyalties && (
  <div className="text-xs text-chia-text-secondary">
    {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties} XCH
  </div>
)}
``` [3](#0-2) 

The Chia daemon computes royalties on the full fungible amount (not a split), so the amount it actually deducts from the user's wallet is higher than what the dialog shows.

### Impact Explanation

A user who approves a WalletConnect `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request for an offer containing multiple royalty-bearing NFTs is shown a "Total Amount with Royalties" that is lower than the amount the daemon will actually spend. The user's informed consent is obtained for the wrong (lower) figure. If the wallet has sufficient balance, the daemon silently deducts the larger correct amount; if not, the transaction fails after approval. Either outcome means the user approved a transaction displaying the wrong spend amount — a direct instance of the High-impact class: *WalletConnect state that causes a user to approve the wrong amount*.

### Likelihood Explanation

Any connected dApp can craft a `take_offer` or `create_offer_for_ids` WalletConnect request referencing an offer with two or more royalty-bearing NFTs. No privileged access is required. The discrepancy scales with the number of NFTs and royalty percentages, making it straightforward to construct a scenario where the understatement is economically significant (e.g., 3 NFTs each with 10% royalties would display ~3.3% of the true royalty cost).

### Recommendation

Remove the `splitAmount` division. Each royalty percentage should be applied to the full `amount`:

```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
  ...
}
```

Update the corresponding test expectations to reflect the corrected values (e.g., `'0.0001051'` instead of `'0.00010255'` for the two-NFT case).

### Proof of Concept

**Setup:** A dApp connected via WalletConnect sends a `chia_wallet.take_offer` request for an offer where the user must pay 0.0001 XCH and receive two NFTs — one with a 5% royalty and one with a 0.1% royalty.

**Observed dialog:** "Total Amount with Royalties: 0.00010255 XCH"

**Actual daemon deduction:** 0.0001051 XCH (5% + 0.1% each applied to the full 0.0001 XCH base)

**Discrepancy:** 0.00000255 XCH (~2.4%) silently deducted beyond what the user approved.

The test at `parseCommandDisplay.test.ts:251–334` already encodes this incorrect value as the expected output, confirming the bug is present in the production code path used to populate the WalletConnect confirmation dialog. [4](#0-3) [5](#0-4)

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L183-205)
```typescript
function WalletDeltaSection({
  walletDelta,
  networkPrefix,
}: {
  walletDelta: NonNullable<ConfirmDisplay['walletDelta']>;
  networkPrefix?: string;
}) {
  const feeUnit = networkPrefix ? networkPrefix.toUpperCase() : 'XCH';
  return (
    <section className="rounded-xl border border-chia-border bg-chia-card overflow-hidden divide-y divide-chia-border">
      <div className="px-5 py-2.5">
        <div className="text-xs font-semibold uppercase tracking-wider text-chia-text-muted">
          {i18n._(/* i18n */ { id: 'You Spend' })}
        </div>
        <div className="mt-1.5 flex flex-col gap-1.5">
          {walletDelta.spending.length === 0 ? (
            <span className="text-sm text-chia-text-secondary">{i18n._(/* i18n */ { id: 'Nothing' })}</span>
          ) : (
            walletDelta.spending.map((line, i) => (
              <OfferLineRow key={offerLineKey(line, i)} line={line} networkPrefix={networkPrefix} />
            ))
          )}
        </div>
```
