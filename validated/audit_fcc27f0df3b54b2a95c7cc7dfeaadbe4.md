### Title
WalletConnect `take_offer` Royalty Amount Understated for Multi-NFT Offers — Causes User to Approve Transactions Spending More Than Displayed - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary

The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the spending amount by the number of NFTs before computing each royalty, causing the displayed `amountWithRoyalties` in the WalletConnect approval dialog to be systematically understated when an offer involves multiple NFTs with royalties. A malicious dApp can craft a multi-NFT `take_offer` WalletConnect request where the user sees a materially lower total cost than what the transaction actually spends, causing the user to approve a transaction that drains more funds than they consented to.

### Finding Description

In `parseCommandDisplay.ts`, the function `formatAmountWithRoyalties` computes the total cost including royalties for display in the WalletConnect confirmation dialog:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The bug: `splitAmount` divides the full spending amount by the count of NFTs before computing each individual royalty. Each royalty should be computed against the **full** spending amount, not a fractional share of it. The correct formula is:

```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

But the code computes:

```
royaltyAmount = Σ ((amount / N) × royaltyPercentage_i / 10_000)
```

which is `1/N` of the correct value.

The existing test confirms this wrong value is accepted as correct:

```
// 2 NFTs: 5% + 0.1% royalties, spending 100,000,000 mojos
// Displayed: 0.00010255 XCH  ← buggy (correct is 0.0001051 XCH)
amountWithRoyalties: '0.00010255'
``` [2](#0-1) 

This `amountWithRoyalties` field is the value surfaced to the user in the WalletConnect command confirmation dialog for `chia_wallet.take_offer`. The actual on-chain royalty payments are computed correctly by the Chia full node — only the display shown to the user before approval is wrong.

**Attacker path:**
1. Malicious dApp connects to the user's wallet via WalletConnect (no privileged access required).
2. Dapp calls `chia_wallet.take_offer` with an offer involving multiple NFTs that carry royalties.
3. The WalletConnect approval dialog renders `amountWithRoyalties` as the total the user will spend — this value is understated by a factor of `1/N` on the royalty component.
4. User approves, believing they are spending the displayed (lower) amount.
5. The actual transaction, constructed by the node, pays the correct (higher) royalties, draining more XCH or CAT than the user consented to.

The understatement scales with the number of NFTs and royalty percentages. With 10 NFTs each carrying 10% royalties and a 1 XCH offer:
- **Displayed:** 1.1 XCH
- **Actual:** 2.0 XCH
- **Undisclosed drain:** 0.9 XCH [3](#0-2) 

### Impact Explanation

**High.** A WalletConnect-connected dApp (unprivileged, no keys required) can cause the user to approve a `take_offer` transaction that spends materially more XCH or CAT than the amount shown in the approval dialog. The user's consent is obtained under false pretenses about the transaction cost. The excess funds are paid as royalties to NFT creators — the attacker's gain is indirect (they can be the NFT creator or royalty recipient), but the user suffers a direct, unrecoverable asset loss beyond what they approved.

This matches the allowed High impact: *"Corruption, spoofing, or unsafe trust of … WalletConnect state that causes a user to approve … the wrong … amount."*

### Likelihood Explanation

Any dApp that can initiate a WalletConnect session can trigger this. The attack requires only that the offer contain two or more NFTs with non-zero royalties — a common, legitimate configuration. No special permissions, leaked keys, or social engineering beyond a normal WalletConnect pairing are needed.

### Recommendation

Replace the `splitAmount` division with the full `amount` for each royalty computation:

```typescript
// Before (buggy):
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

Update the corresponding test expectation from `'0.00010255'` to `'0.0001051'` to reflect the correct value.

### Proof of Concept

From the existing test in `parseCommandDisplay.test.ts` (lines 251–335):

- Offer: 2 NFTs offered, 100,000,000 mojos (0.0001 XCH) requested
- NFT 1 royalty: 500 basis points (5%)
- NFT 2 royalty: 10 basis points (0.1%)

**Correct total:** `100,000,000 + (100,000,000 × 500/10,000) + (100,000,000 × 10/10,000)` = `105,100,000` mojos = **0.0001051 XCH**

**Displayed total (buggy):** `splitAmount = 50,000,000`; royalties = `2,500,000 + 50,000 = 2,550,000`; total = `102,550,000` mojos = **0.00010255 XCH**

The test asserts `amountWithRoyalties: '0.00010255'`, confirming the understated value is what reaches the WalletConnect approval UI. The user approves 0.00010255 XCH but the transaction spends 0.0001051 XCH. [1](#0-0) [4](#0-3)

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L251-335)
```typescript
  it('shows the take-offer fungible total with multiple NFT creator royalties', async () => {
    const firstNftLauncherId = '0fbdbe7e1392f248f4ce3f8b1497496f056db6eb3856990ea3f697e28ec082c4';
    const secondNftLauncherId = '022a8c5c7c111111111111111111111111111111111111111111111111111111';
    mockGetWalletInfos.mockResolvedValue({});
    mockGetOfferSummary.mockResolvedValue(
      makeOfferSummary({
        offered: {
          [firstNftLauncherId]: '1',
          [secondNftLauncherId]: '1',
        },
        requested: {
          xch: '100000000',
        },
        infos: {
          [firstNftLauncherId]: {
            type: 'singleton',
            also: {
              type: 'metadata',
              also: {
                type: 'ownership',
                transfer_program: {
                  type: 'royalty transfer program',
                  royalty_percentage: '500',
                },
              },
            },
          },
          [secondNftLauncherId]: {
            type: 'singleton',
            also: {
              type: 'metadata',
              also: {
                type: 'ownership',
                transfer_program: {
                  type: 'royalty transfer program',
                  royalty_percentage: '10',
                },
              },
            },
          },
        },
      }),
    );
    mockNftGetInfo
      .mockResolvedValueOnce({
        success: true,
        nft_info: {
          data_uris: [],
          royalty_percentage: 500,
        },
      })
      .mockResolvedValueOnce({
        success: true,
        nft_info: {
          data_uris: [],
          royalty_percentage: 10,
        },
      });

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
  });
```
