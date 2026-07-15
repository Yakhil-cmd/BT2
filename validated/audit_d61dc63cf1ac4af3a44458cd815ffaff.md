### Title
WalletConnect `take_offer` Royalty Spoofing via Untrusted Driver Dict Understates Actual XCH/CAT Spend - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary

When a WalletConnect dApp sends a `chia_wallet.take_offer` command, the GUI computes the `amountWithRoyalties` shown in the confirmation dialog using the `royalty_percentage` embedded in the offer file's driver dict — data fully controlled by the malicious maker. A best-effort override via `nftGetInfo` can silently fail, leaving the spoofed value in place. The user approves what appears to be a royalty-free (or low-royalty) spend; the wallet then enforces the actual on-chain royalty, causing the user to spend more XCH/CAT than they consented to.

### Finding Description

`parseCommandDisplay` handles `chia_wallet.take_offer` at line 439. It calls `getOfferSummary` on the raw offer string, then extracts royalty percentages via `offerSummaryRoyaltyPercentages`: [1](#0-0) 

`offerSummaryRoyaltyPercentages` reads directly from `summary.infos`, which is the wallet RPC's re-serialisation of the offer file's driver dict — maker-controlled data: [2](#0-1) 

The royalty percentage is extracted from the nested `transfer_program.royalty_percentage` field inside the driver dict: [3](#0-2) 

Inside `parseWalletDeltaItem`, the code attempts a best-effort override by calling `nftGetInfo` to fetch the on-chain royalty: [4](#0-3) 

The catch block at line 324 silently swallows any failure and leaves `result.royaltyPercentage` set to the driver-dict value. The comment confirms this is intentional: *"NFT type has already been resolved from offer data; metadata is best effort."*

`withRoyaltyTotals` then uses the NFT item's `royaltyPercentage` to compute `amountWithRoyalties` for every fungible asset on the spending side: [5](#0-4) 

If the driver dict carries `royalty_percentage: 0` (or any value lower than the real royalty), and `nftGetInfo` fails, `amountWithRoyalties` is computed as the bare base amount. The user sees and approves that figure. The wallet then enforces the actual on-chain royalty puzzle, spending the correct (higher) amount.

### Impact Explanation

A user approves a WalletConnect `take_offer` transaction believing they are spending, for example, 1 XCH. The wallet executes the spend bundle with the correct on-chain royalty (e.g., 10%), deducting 1.1 XCH. The user has consented to 1 XCH but loses 1.1 XCH — a direct, unprivileged-attacker-induced asset loss through WalletConnect approval hijack.

This matches: **High — Corruption or spoofing of WalletConnect state that causes a user to approve the wrong amount.**

### Likelihood Explanation

- The attacker only needs to craft a standard Chia offer file with a zeroed or reduced `royalty_percentage` in the driver dict and deliver it via any WalletConnect-connected dApp.
- `nftGetInfo` fails silently whenever the local wallet has not yet synced the NFT's coin (common when buying an NFT the user does not own), the wallet is mid-sync, or the RPC returns `success: false`.
- No special privileges, leaked keys, or cryptographic breaks are required.

### Recommendation

Replace the best-effort fallback with a hard requirement: if `nftGetInfo` succeeds and returns a `royalty_percentage`, use it; if it fails, **do not display `amountWithRoyalties` at all** (or display a warning that the royalty could not be verified) rather than silently falling back to the maker-supplied driver dict value. The confirmation dialog should never show a royalty-inclusive total derived solely from untrusted offer data.

### Proof of Concept

1. Attacker mints an NFT with `royalty_percentage = 1000` (10%).
2. Attacker creates a valid Chia offer for that NFT requesting 1 XCH, but sets `royalty_percentage: 0` in the driver dict of the offer file.
3. Attacker's WalletConnect dApp sends `chia_wallet.take_offer` with this offer string to the victim's GUI.
4. `offerSummaryRoyaltyPercentages` reads `royalty_percentage: 0` from `summary.infos`.
5. `nftGetInfo` fails (NFT not yet in victim's wallet DB) — catch block fires, no override.
6. `formatAmountWithRoyalties` computes `royaltyAmount = 0`; dialog shows **"You will spend: 1 XCH"**.
7. Victim clicks Approve.
8. Wallet enforces the on-chain royalty puzzle; spend bundle includes 0.1 XCH royalty payment.
9. Victim's balance decreases by 1.1 XCH — 0.1 XCH more than the approved display.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L60-81)
```typescript
function royaltyPercentageForDriverInfo(driverInfo: unknown): number | undefined {
  if (!isPlainObject(driverInfo)) {
    return undefined;
  }

  const { also } = driverInfo;
  if (!isPlainObject(also)) {
    return undefined;
  }

  const ownershipLayer = also.also;
  if (!isPlainObject(ownershipLayer)) {
    return undefined;
  }

  const transferProgram = ownershipLayer.transfer_program;
  if (!isPlainObject(transferProgram)) {
    return undefined;
  }

  return parseRoyaltyPercentage(transferProgram.royalty_percentage);
}
```

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L302-329)
```typescript
  if (assetKind === 'nft') {
    const nftId = hexToNftId(key);

    const result: DisplayWalletDeltaItem = {
      kind: 'nft',
      nftId,
      royaltyPercentage,
    };

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

    return result;
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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L444-458)
```typescript
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
```
