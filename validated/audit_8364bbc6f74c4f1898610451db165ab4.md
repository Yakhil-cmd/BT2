### Title
WalletConnect Offer Approval Displays Understated Royalty Total for Multi-NFT Offers — (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

---

### Summary

`formatAmountWithRoyalties` in `parseCommandDisplay.ts` incorrectly divides the fungible spend amount by the number of NFTs before applying each royalty percentage, instead of applying each royalty to the full amount. The WalletConnect approval dialog therefore shows a "Total Amount with Royalties" that is systematically lower than what the user will actually spend when taking or creating an offer that involves multiple royalty-bearing NFTs.

---

### Finding Description

The function `formatAmountWithRoyalties` computes the royalty-inclusive total shown in the WalletConnect `Confirm` dialog:

```ts
// packages/gui/src/electron/commands/parseCommandDisplay.ts  lines 363-368
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← wrong
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The correct formula is to apply each NFT's royalty to the **full** amount:

```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

The actual formula computes:

```
royaltyAmount = (amount / N) × Σ (royaltyPercentage_i / 10_000)
              = amount × (average_royalty / 10_000)
```

This is equivalent to applying only the **average** royalty once, not each royalty to the full amount. The result is always lower than the true total when N > 1.

**Concrete example** — user takes an offer to receive 2 NFTs (royalties 5 % and 10 %) by spending 1 XCH:

| | Displayed | Correct |
|---|---|---|
| Royalty paid | 0.075 XCH | 0.15 XCH |
| Total shown | 1.075 XCH | 1.15 XCH |

The discrepancy grows with the number of NFTs and their royalty rates.

`formatAmountWithRoyalties` is called from `withRoyaltyTotals`, which is called from `walletDeltaToDisplay`, which is called for both `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids` in `parseCommandDisplay`: [2](#0-1) 

The resulting `amountWithRoyalties` field is rendered in the `Confirm` dialog under **"You Spend"** → **"Total Amount with Royalties"**, which is the primary signal a user relies on before clicking **Confirm**: [3](#0-2) 

---

### Impact Explanation

A WalletConnect-connected dApp can craft a `take_offer` or `create_offer_for_ids` request involving multiple NFTs whose royalties it controls (as the NFT creator/royalty recipient). The approval dialog shows a royalty total that is a fraction of the true cost. The user approves believing they are spending X, but the wallet daemon charges the correct (higher) amount Y. The excess royalty flows to the attacker-controlled royalty address.

This satisfies the **High** criterion: *"Corruption, spoofing, or unsafe trust of… WalletConnect state that causes a user to approve… the wrong… amount."*

---

### Likelihood Explanation

Any WalletConnect-paired dApp can trigger this path by issuing `chia_wallet.take_offer` with a multi-NFT offer. No special privileges are required. The royalty percentages are read from on-chain NFT data or the offer's `infos` field, both of which an attacker who minted the NFTs controls. The bug is deterministic and reproducible whenever N ≥ 2 royalty-bearing NFTs appear on the receiving side.

---

### Recommendation

Replace the split-then-sum formula with the correct per-NFT-full-amount formula:

```ts
// packages/gui/src/electron/commands/parseCommandDisplay.ts
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

Remove the `splitAmount` variable entirely. Update the corresponding test expectations in `parseCommandDisplay.test.ts` (the multi-NFT case currently asserts the wrong value `0.00010255` instead of the correct `0.0001051`). [4](#0-3) 

---

### Proof of Concept

1. Attacker mints two NFTs with royalty addresses they control: NFT-A (5 %, i.e. 500 basis points) and NFT-B (10 %, i.e. 1000 basis points).
2. Attacker creates an offer: give NFT-A + NFT-B, receive 1 XCH.
3. Attacker sends the offer string to the victim via a WalletConnect-paired dApp (`chia_wallet.take_offer`).
4. Victim's approval dialog shows:
   - **You Spend**: `1 XCH` / **Total Amount with Royalties**: `1.075 XCH` ← incorrect
5. Victim clicks **Confirm**.
6. Wallet daemon correctly charges `1.15 XCH` (1 + 0.05 + 0.10).
7. Attacker receives `0.15 XCH` in royalties; victim paid `0.075 XCH` more than the dialog indicated.

The root cause is the `splitAmount` division on line 363 of `parseCommandDisplay.ts`, which is the direct analog of the external report's use of the wrong borrow index — a wrong context parameter substituted into a financial calculation, producing a systematically incorrect result shown to the user at the moment of approval. [5](#0-4)

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L431-434)
```typescript
  return {
    spending: withRoyaltyTotals(spendingItems, spending, receivingLines),
    receiving: withRoyaltyTotals(receivingItems, receiving, spendingLines),
    fee: fee !== undefined ? mojoToChiaLocaleString(fee) : undefined,
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
