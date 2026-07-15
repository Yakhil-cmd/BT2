Now I have enough context to write the finding. The key pattern is clear:

- **External bug**: relayer supplies `_tokenTypeIndex` without validation against the trusted evidence structure
- **Chia GUI analog**: a dApp via WalletConnect supplies `driver_dict` (including `royalty_percentage`) for `chia_createOfferForIds`, and the confirmation dialog's "Total Amount with Royalties" is computed entirely from this dApp-controlled parameter — never cross-checked against on-chain NFT data

### Title
WalletConnect dApp Can Spoof NFT Royalty Amount in `chia_createOfferForIds` Confirmation Dialog — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

When a WalletConnect dApp invokes `chia_createOfferForIds`, the `royalty_percentage` used to compute and display the "Total Amount with Royalties" in the approval dialog is read exclusively from the dApp-controlled `driver_dict` parameter. No cross-check against on-chain NFT data is performed. A malicious dApp can set `royalty_percentage: "0"` to hide royalties entirely, causing the user to approve an offer whose displayed spending amount is lower than what the offer actually requires, or set an arbitrarily inflated value to cause the user to reject a legitimate offer.

### Finding Description

In `parseCommandDisplay.ts`, the `chia_wallet.create_offer_for_ids` branch calls `createOfferRoyaltyPercentages`, which reads `royalty_percentage` directly from the dApp-supplied `driver_dict`: [1](#0-0) 

`royaltyPercentageForDriverInfo` extracts the value from `driverDict[assetId].also.also.transfer_program.royalty_percentage`: [2](#0-1) 

This royalty percentage is then used in `formatAmountWithRoyalties` to compute the `amountWithRoyalties` field shown in the confirmation dialog: [3](#0-2) 

The `driver_dict` is a parameter the dApp supplies freely alongside the `offer` dict. The `Commands.ts` definition confirms it is accepted as a raw `json` field from the dApp: [4](#0-3) 

**Contrast with `take_offer`**: In the `take_offer` path, royalty percentages are derived from the offer summary returned by the trusted daemon (`getOfferSummary`), and then overridden by a second trusted call (`nftGetInfo`) inside `parseWalletDeltaItem`. Neither trusted source is consulted for `create_offer_for_ids`. [5](#0-4) 

The existing `assetKindForDriverDictAssetId` validation only checks that `tail`/`launcher_id` matches the asset ID key — it does not validate `royalty_percentage`: [6](#0-5) 

### Impact Explanation

The user sees a misleading "Total Amount with Royalties" (or no royalty line at all) in the WalletConnect approval dialog. If the dApp suppresses the royalty (`royalty_percentage: "0"`), the user approves an offer believing they will spend exactly the base XCH/CAT amount. The backend receives the dApp-controlled `driver_dict` and constructs the offer accordingly. When the offer is accepted on-chain, the NFT puzzle enforces the actual royalty, causing the offer to fail (assets locked until cancelled) or the user to spend more than the approved display indicated. This is a direct case of WalletConnect state spoofing causing a user to approve the wrong amount — matching the High impact category.

### Likelihood Explanation

Any dApp that has been granted `chia_createOfferForIds` permission by the user can trigger this. The WalletConnect pairing and command-allow checks are enforced: [7](#0-6) 

But once a dApp is paired and the command is allowed, it controls `driver_dict` entirely. No additional privilege is required beyond a legitimate WalletConnect pairing.

### Recommendation

For `create_offer_for_ids`, after resolving the NFT asset ID from the `driver_dict`, call `nftGetInfo` (as already done in the `take_offer` path inside `parseWalletDeltaItem`) to fetch the actual on-chain `royalty_percentage` and use that value instead of the dApp-supplied one. If `nftGetInfo` fails or returns no royalty data, fall back to displaying no royalty estimate rather than trusting the dApp-provided value. [8](#0-7) 

### Proof of Concept

A malicious dApp sends the following WalletConnect request after pairing:

```json
{
  "command": "chia_createOfferForIds",
  "params": {
    "offer": {
      "1": "-1000000000000",
      "<real_nft_launcher_id>": "1"
    },
    "driver_dict": {
      "<real_nft_launcher_id>": {
        "type": "singleton",
        "launcher_id": "0x<real_nft_launcher_id>",
        "also": {
          "type": "metadata",
          "also": {
            "type": "ownership",
            "transfer_program": {
              "type": "royalty transfer program",
              "royalty_percentage": "0"
            }
          }
        }
      }
    }
  }
}
```

`createOfferRoyaltyPercentages` reads `royalty_percentage: "0"` from the dApp dict. `formatAmountWithRoyalties` returns `undefined` (no royalty surcharge). The confirmation dialog shows only "Spending: 1 XCH" with no royalty line. The user approves. The actual NFT carries, say, a 250 basis-point (2.5%) royalty enforced on-chain, so the offer either fails at acceptance or the user's locked assets behave unexpectedly relative to what they approved.

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L134-163)
```typescript
function assetKindForDriverDictAssetId(
  assetId: string,
  driverDict: Record<string, unknown>,
): AssetDisplayKind | undefined {
  const driverInfo = driverDict[assetId] ?? driverDict[`0x${assetId}`];
  if (driverInfo === undefined) {
    return undefined;
  }

  if (!isPlainObject(driverInfo) || typeof driverInfo.type !== 'string') {
    throw new Error('Driver Dict is not valid');
  }

  const driverType = driverInfo.type.toLowerCase();

  switch (driverType) {
    case 'cat':
      if (normalizeDriverAssetId(driverInfo.tail) !== assetId) {
        throw new Error('Driver Dict is not valid');
      }
      return 'cat';
    case 'singleton':
      if (normalizeDriverAssetId(driverInfo.launcher_id) !== assetId) {
        throw new Error('Driver Dict is not valid');
      }
      return 'nft';
    default:
      throw new Error('Driver Dict is not valid');
  }
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L239-261)
```typescript
function createOfferRoyaltyPercentages(
  walletDelta: WalletDelta,
  driverDict: Record<string, unknown>,
): AssetRoyaltyPercentages {
  const royaltyPercentages: AssetRoyaltyPercentages = {
    spending: {},
    receiving: {},
  };

  for (const assetId of Object.keys(walletDelta.spending)) {
    royaltyPercentages.spending[assetId] = royaltyPercentageForDriverInfo(
      driverDict[assetId] ?? driverDict[`0x${assetId}`],
    );
  }

  for (const assetId of Object.keys(walletDelta.receiving)) {
    royaltyPercentages.receiving[assetId] = royaltyPercentageForDriverInfo(
      driverDict[assetId] ?? driverDict[`0x${assetId}`],
    );
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

**File:** packages/gui/src/electron/commands/Commands.ts (L293-293)
```typescript
      { name: 'driver_dict', label: () => i18n._(/* i18n */ { id: 'Driver Dict' }), type: 'json' },
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L28-44)
```typescript
  // verify if the command is allowed for this pair
  if (!pair.commands.includes(command)) {
    throw new WcError(`Command not allowed for this pair.`, WcErrorCode.UNAUTHORIZED_METHOD);
  }

  const { fingerprint } = params;

  // verify if the network is the same as the pair's network
  if (isMainnetValue !== pair.mainnet) {
    throw new WcError(`Network mismatch`, WcErrorCode.UNSUPPORTED_CHAINS);
  }

  // verify if the requested fingerprint is allowed for this pair
  const requestedFingerprint = fingerprint ?? loggedInFingerprint;
  if (typeof requestedFingerprint !== 'number' || !requestedFingerprint || requestedFingerprint !== pair.fingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }
```
