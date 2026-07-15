### Title
WalletConnect `take_offer` Confirmation Dialog Trusts Attacker-Controlled Royalty Percentage, Understating Total Spend - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary
When a WalletConnect dApp sends a `chia_wallet.take_offer` request, the GUI's confirmation dialog computes and displays "Total Amount with Royalties" using the `royalty_percentage` embedded in the offer's driver dict — data fully controlled by the offer maker (attacker). The on-chain royalty is only fetched via `nftGetInfo` as a best-effort override, and that override is gated behind a `data_uris` presence check. If `nftGetInfo` fails or the NFT has no `data_uris`, the attacker-supplied royalty (e.g., 0%) is used for the display while the actual blockchain transaction enforces the real on-chain royalty (e.g., 10%). The user approves believing they will spend X XCH, but the executed transaction spends X + real_royalty XCH.

### Finding Description

**Step 1 — Royalty sourced from attacker-controlled offer data**

In `parseCommandDisplay` for `chia_wallet.take_offer`, the offer summary is fetched from the daemon:

```
const offerSummary = await getOfferSummary(params.offer);
const royaltyPercentages = offerSummaryRoyaltyPercentages(summary);
```

`offerSummaryRoyaltyPercentages` reads `royalty_percentage` directly from `summary.infos`, which is the driver dict embedded in the offer blob by the maker: [1](#0-0) 

The driver dict is authored by the offer maker and is not independently verified at this point.

**Step 2 — On-chain override is gated behind `data_uris` presence**

Inside `parseWalletDeltaItem`, `nftGetInfo` is called to fetch the real on-chain royalty. However, the royalty override is nested inside a check for `nftInfo.nft_info.data_uris`: [2](#0-1) 

If `nftGetInfo` returns `success: false`, throws, or returns a response where `nft_info.data_uris` is absent/null, the royalty stays at the attacker-supplied value from Step 1. The catch block explicitly treats this as non-fatal: [3](#0-2) 

**Step 3 — Spoofed royalty propagates to the "Total Amount with Royalties" display**

`withRoyaltyTotals` reads `royaltyPercentage` from the NFT items on the receiving side and uses it to compute `amountWithRoyalties` for the spending side: [4](#0-3) 

**Step 4 — Confirmation dialog presents the spoofed total to the user**

The `Confirm` component renders `amountWithRoyalties` as "Total Amount with Royalties" in the "You Spend" section, which is the primary financial summary the user reads before clicking Confirm: [5](#0-4) 

### Impact Explanation

A victim using WalletConnect to accept an NFT offer approves a transaction based on a displayed total that excludes the real royalty. The actual spend bundle submitted to the blockchain enforces the on-chain royalty (encoded in the NFT puzzle), so the victim's wallet pays `base_amount + real_royalty` — more than the confirmed amount. This is a direct, unprivileged-attacker-induced accounting discrepancy that causes the user to approve the wrong amount, matching the High impact category: *"unsafe trust of offer, NFT metadata, or WalletConnect state that causes a user to approve the wrong amount."*

### Likelihood Explanation

The attack requires `nftGetInfo` to fail or return without `data_uris`. This is realistic when:
- The NFT was minted recently and has not yet propagated to the victim's node at the time of the WalletConnect request.
- The victim's node is partially synced.
- The attacker deliberately times the offer delivery to precede full sync.

The attacker controls the offer blob entirely and can set `royalty_percentage` to any value (including 0) in the driver dict. No special privileges are required beyond the ability to create a WalletConnect session and send a `take_offer` request.

### Recommendation

1. **Decouple the royalty override from the `data_uris` check.** Move the `royalty_percentage` override outside the `data_uris` guard so it applies whenever `nftGetInfo` succeeds and the field is present:

```typescript
if (nftInfo && nftInfo.success && nftInfo.nft_info) {
  if (nftInfo.nft_info.data_uris) {
    const previewUrl = nftInfo.nft_info.data_uris.find((u) => isValidURL(u));
    if (previewUrl) result.previewUrl = previewUrl;
  }
  if ('royalty_percentage' in nftInfo.nft_info) {
    result.royaltyPercentage = parseRoyaltyPercentage(nftInfo.nft_info.royalty_percentage);
  }
}
```

2. **When `nftGetInfo` fails, suppress `amountWithRoyalties` entirely** (or show a warning that the royalty could not be verified) rather than silently falling back to the attacker-supplied value.

3. **Never trust `royalty_percentage` from the offer's driver dict as a display value** without on-chain confirmation. The driver dict is maker-authored and unverified.

### Proof of Concept

1. Attacker mints NFT `X` with 10% on-chain royalty.
2. Attacker creates an offer: "NFT X for 1 XCH" with `royalty_percentage: 0` in the driver dict.
3. Attacker establishes a WalletConnect session with the victim's Chia GUI and sends `chia_wallet.take_offer` with the crafted offer string.
4. GUI calls `getOfferSummary` → daemon parses the offer → `summary.infos[nftX].transfer_program.royalty_percentage = 0`.
5. `offerSummaryRoyaltyPercentages` returns `{ receiving: { nftX: 0 } }`.
6. `nftGetInfo(nftX)` fails (NFT not yet synced to victim's node) → catch block swallows the error.
7. `formatAmountWithRoyalties` computes `royaltyAmount = (0 / 10000) * 1_000_000_000_000 = 0`.
8. Confirmation dialog shows: **"You Spend: 1 XCH — Total Amount with Royalties: 1 XCH"**.
9. Victim clicks Confirm.
10. Daemon builds the actual spend bundle using the on-chain 10% royalty → victim's wallet spends **1.1 XCH**.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L184-206)
```typescript
function offerSummaryRoyaltyPercentages(offerSummary: OfferSummaryForDisplay): AssetRoyaltyPercentages {
  const royaltyPercentages: AssetRoyaltyPercentages = {
    spending: {},
    receiving: {},
  };

  const { infos } = offerSummary;
  if (!isPlainObject(infos)) {
    return royaltyPercentages;
  }

  for (const assetId of Object.keys(offerSummary.requested)) {
    const parsedAssetId = assetId === 'xch' ? '1' : assetId;
    royaltyPercentages.spending[parsedAssetId] = royaltyPercentageForDriverInfo(infos[assetId]);
  }

  for (const assetId of Object.keys(offerSummary.offered)) {
    const parsedAssetId = assetId === 'xch' ? '1' : assetId;
    royaltyPercentages.receiving[parsedAssetId] = royaltyPercentageForDriverInfo(infos[assetId]);
  }

  return royaltyPercentages;
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L311-327)
```typescript
    try {
      const nftInfo = await nftGetInfo(key);
      if (nftInfo && nftInfo.success && nftInfo.nft_info && nftInfo.nft_info.data_uris) {
        const previewUrl = nftInfo.nft_info.data_uris.find((u) => isValidURL(u));

        if (previewUrl) {
          result.previewUrl = previewUrl;
        }

        if ('royalty_percentage' in nftInfo.nft_info) {
          result.royaltyPercentage = parseRoyaltyPercentage(nftInfo.nft_info.royalty_percentage);
        }
      }
    } catch {
      // NFT type has already been resolved from offer data; metadata is best effort.
    }

```

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```
