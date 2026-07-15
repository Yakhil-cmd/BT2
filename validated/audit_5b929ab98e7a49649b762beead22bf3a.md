### Title
Incorrect Multi-NFT Royalty Accounting in WalletConnect Confirmation Underreports Total Spend - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary

`formatAmountWithRoyalties` in `parseCommandDisplay.ts` divides the fungible amount by the number of NFTs before computing each royalty, producing a total that is systematically lower than what the blockchain will actually charge. The WalletConnect confirmation dialog surfaces this incorrect figure as "Total Amount with Royalties," causing a user to approve a `take_offer` or `create_offer_for_ids` command while believing they are spending less XCH/CAT than the transaction will actually deduct.

### Finding Description

The function `formatAmountWithRoyalties` is responsible for computing the royalty-inclusive total shown in the WalletConnect signing dialog:

```ts
// packages/gui/src/electron/commands/parseCommandDisplay.ts
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← wrong division
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) =>
    total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The Chia protocol computes royalties independently per NFT, each applied to the **full** fungible amount. The GUI instead divides the amount by the count of NFTs first, so each royalty is applied to only a fraction of the real spend. With *N* NFTs the displayed royalty is `1/N` of the correct value.

**Concrete example (two NFTs, 5 % + 0.1 % royalties, 1 XCH purchase):**

| | Displayed | Correct |
|---|---|---|
| Royalty | 0.025 XCH | 0.051 XCH |
| Total | **1.025 XCH** | **1.051 XCH** |

The existing test suite encodes this wrong behaviour as the expected output:

```ts
// parseCommandDisplay.test.ts – two NFTs, royalty_percentage 500 + 10
amountWithRoyalties: '0.00010255',   // test passes with the buggy formula
// correct value would be '0.0001051'
``` [2](#0-1) 

The incorrect total is then rendered in the WalletConnect confirmation dialog under the label **"Total Amount with Royalties"**:

```tsx
// Confirm.tsx
{line.amountWithRoyalties && (
  <div className="text-xs text-chia-text-secondary">
    {i18n._({ id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties} XCH
  </div>
)}
``` [3](#0-2) 

### Impact Explanation

A user reviewing a WalletConnect `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request that involves multiple NFTs sees a "Total Amount with Royalties" that is materially lower than the amount the blockchain will deduct. The user approves based on the displayed figure; the wallet daemon executes the offer at the correct (higher) royalty-inclusive cost. The gap grows with the number of NFTs and the magnitude of their royalty percentages. This is a WalletConnect-state accounting error that causes a user to approve the wrong spend amount — matching the High impact criterion.

### Likelihood Explanation

- Multi-NFT offers are a supported and documented feature of the Chia offer system.
- WalletConnect dApps routinely construct bundle offers containing several NFTs.
- No user action beyond accepting a legitimate-looking offer is required; the attacker only needs to craft an offer with two or more NFTs that carry royalties.
- The attacker is fully unprivileged — they need no access to the victim's keys or machine.

### Recommendation

Remove the `splitAmount` division. Each royalty percentage must be applied to the full `amount`:

```ts
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) =>
    total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test expectations to reflect the corrected values.

### Proof of Concept

Given an offer where the user is buying two NFTs (royalty percentages 500 bp and 10 bp) for 100 000 000 mojos (0.0001 XCH):

**Current (buggy) output shown in WalletConnect dialog:**
```
Total Amount with Royalties: 0.00010255 XCH
```
*(splitAmount = 50 000 000; royalties = 2 500 000 + 50 000 = 2 550 000)*

**Correct value the blockchain charges:**
```
Total Amount with Royalties: 0.0001051 XCH
```
*(royalties = 5 000 000 + 100 000 = 5 100 000)*

The user approves seeing `0.00010255 XCH` but the wallet deducts `0.0001051 XCH`. The discrepancy scales linearly with the number of NFTs and their royalty rates — e.g. five NFTs each at 10 % royalty on a 10 XCH purchase would display `10.5 XCH` while the blockchain charges `15 XCH`.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L363-368)
```typescript
  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
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
