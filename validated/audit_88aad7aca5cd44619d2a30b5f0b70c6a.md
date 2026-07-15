### Title
WalletConnect `take_offer` Approval Shows Spoofed `amountWithRoyalties` via Unvalidated Offer `infos.royalty_percentage` - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary

The `parseCommandDisplay` function, which generates the wallet-delta display shown to users in the WalletConnect approval dialog for `chia_wallet.take_offer` commands, computes `amountWithRoyalties` using the `royalty_percentage` embedded in the offer file's `infos` field. This field is fully attacker-controlled. No cross-check against on-chain NFT data is performed. A malicious dApp can craft an offer with a suppressed (e.g., zero) `royalty_percentage` in the `infos`, causing the approval dialog to display a lower total spend than the wallet will actually deduct, inducing the user to approve a transaction that costs more XCH than shown.

### Finding Description

In `parseCommandDisplay.ts`, when handling a `chia_wallet.take_offer` WalletConnect command, the function calls `offerSummaryRoyaltyPercentages(summary)` to extract royalty percentages for display:

```typescript
const royaltyPercentages = offerSummaryRoyaltyPercentages(summary);
```

`offerSummaryRoyaltyPercentages` reads directly from `offerSummary.infos`, which is derived from the offer file's driver dict — data supplied by the party who created the offer (the attacker):

```typescript
royaltyPercentages.receiving[parsedAssetId] = royaltyPercentageForDriverInfo(infos[assetId]);
```

`royaltyPercentageForDriverInfo` traverses the nested `also.also.transfer_program.royalty_percentage` path in the driver info and returns whatever integer is there, with no validation against the NFT's on-chain puzzle hash.

These royalty percentages are then fed into `formatAmountWithRoyalties`, which computes the `amountWithRoyalties` field shown in the approval dialog:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

The offer validity check (`getOfferSummary`) only verifies that the offer string is cryptographically parseable — it does not validate that the `royalty_percentage` in the driver dict matches the NFT's actual on-chain royalty puzzle. The actual spend bundle constructed by the wallet daemon when `take_offer` is executed enforces the real on-chain royalty, not the one in the display.

### Impact Explanation

A malicious dApp sends a WalletConnect `take_offer` request containing an offer where the NFT's driver dict has `royalty_percentage` set to `0` (or any value lower than the actual on-chain royalty). The approval dialog shows `amountWithRoyalties` equal to the base XCH amount with no royalty added. The user approves. The wallet daemon then constructs the spend bundle enforcing the real on-chain royalty, deducting `base_amount + real_royalty` from the user's wallet — more than the approved display indicated. This is a direct, concrete XCH loss caused by a spoofed approval display.

This maps to the allowed High impact: *"Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status."*

### Likelihood Explanation

Any unprivileged actor operating a dApp connected via WalletConnect can craft an offer file with an arbitrary `royalty_percentage` in the driver dict. The offer string is passed directly to `parseCommandDisplay` as `params.offer`. No privilege, key access, or host compromise is required. The attack requires only that the victim has WalletConnect connected to a malicious dApp and is induced to accept an NFT offer.

### Recommendation

In `offerSummaryRoyaltyPercentages`, do not trust the `royalty_percentage` from the offer's `infos` field for display purposes. Instead, resolve the NFT's launcher ID from the offer summary and fetch the actual `royalty_percentage` from the wallet daemon via `nft_get_info` (as is already done in the `NFTOfferViewer` path via `useNFT(launcherId)`). Use the on-chain value for computing `amountWithRoyalties`. If the on-chain lookup fails or is unavailable, display the royalty amount as unknown rather than using the offer-supplied value.

### Proof of Concept

1. Attacker operates a dApp connected to victim's wallet via WalletConnect.
2. Attacker creates a valid Chia offer: NFT (with 10% on-chain royalty) offered in exchange for 1 XCH.
3. Attacker modifies the offer's driver dict to set `royalty_percentage` to `0` in the `infos` field.
4. Attacker sends a `chia_wallet.take_offer` WalletConnect request with this crafted offer.
5. `parseCommandDisplay` calls `offerSummaryRoyaltyPercentages`, reads `royalty_percentage = 0` from the offer infos.
6. `formatAmountWithRoyalties` computes `amountWithRoyalties = 1 XCH` (no royalty added).
7. Approval dialog shows: *"You will spend: 1 XCH (total with royalties: 1 XCH)"*.
8. User approves.
9. Wallet daemon enforces the real 10% royalty; actual deduction is 1.1 XCH.
10. User loses 0.1 XCH more than the approved display indicated.

**Relevant code locations:**

`offerSummaryRoyaltyPercentages` reads unvalidated royalty from offer infos: [1](#0-0) 

`royaltyPercentageForDriverInfo` extracts the attacker-supplied value: [2](#0-1) 

`formatAmountWithRoyalties` uses it to compute the displayed total: [3](#0-2) 

`parseCommandDisplay` orchestrates the flow for `take_offer`: [4](#0-3) 

By contrast, the direct offer import path (`NFTOfferViewer`) correctly fetches the on-chain royalty via `useNFT(launcherId)` and uses `nft.royaltyPercentage` — the WalletConnect path lacks this safeguard: [5](#0-4)

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L184-205)
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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L438-460)
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
  }
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L366-394)
```typescript
  const { nft } = useNFT(launcherId);
  const { amount, assetId, assetType } = getNFTPriceWithoutRoyalties(summary) ?? {};
  const { lookupByAssetId } = useAssetIdName();
  const assetIdInfo = assetId ? lookupByAssetId(assetId) : undefined;
  const displayName = assetIdInfo?.displayName ?? t`Unknown CAT`;

  const { data: wallets, isLoading: isLoadingWallets } = useGetWalletsQuery();
  const { offers, isLoading: isOffersLoading } = useWalletOffers(-1, 0, true, false, 'RELEVANCE', false);

  const isLoading = isLoadingWallets || isOffersLoading;

  const nftSaleInfo = useMemo(() => {
    if (!exchangeType || amount === undefined || !nft || nft.royaltyPercentage === undefined) {
      return undefined;
    }

    const royaltyPercentage = convertRoyaltyToPercentage(nft.royaltyPercentage);
    const xchMakerFee = mojoToChia(makerFee);

    return {
      ...calculateNFTRoyalties(
        amount,
        parseFloat(xchMakerFee),
        convertRoyaltyToPercentage(nft.royaltyPercentage),
        exchangeType,
      ),
      royaltyPercentage,
    };
  }, [amount, exchangeType, makerFee, nft]);
```
