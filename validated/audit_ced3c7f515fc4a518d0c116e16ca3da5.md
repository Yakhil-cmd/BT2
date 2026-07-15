### Title
WalletConnect `create_offer_for_ids` Displays Dapp-Controlled Royalty Percentage as "Total Amount with Royalties" Without On-Chain Verification — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

---

### Summary

When a WalletConnect dapp sends `chia_wallet.create_offer_for_ids`, the GUI computes and displays a "Total Amount with Royalties" figure in the approval dialog using a royalty percentage sourced entirely from the dapp-supplied `driver_dict`. The on-chain override via `nftGetInfo` is gated on `nftInfo.success` being true, which fails whenever the NFT is not locally known. A malicious dapp can supply `royalty_percentage: 0` (or any suppressed value) in the `driver_dict`, causing the user to see a lower total than the actual on-chain royalty obligation, and approve the offer under false accounting.

---

### Finding Description

In `parseCommandDisplay.ts`, the `create_offer_for_ids` branch calls `createOfferRoyaltyPercentages(walletDelta, driverDict)` to extract royalty percentages for display:

```typescript
// line 473-475
const driverDict = params.driver_dict ?? {};
const assetKinds = createOfferAssetKinds(walletDelta, walletInfos, driverDict);
const royaltyPercentages = createOfferRoyaltyPercentages(walletDelta, driverDict);
```

`createOfferRoyaltyPercentages` reads directly from the dapp-supplied `driver_dict` with no verification:

```typescript
// lines 248-258
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
```

These percentages seed `result.royaltyPercentage` in `parseWalletDeltaItem` (line 308). The code then attempts an on-chain override via `nftGetInfo`:

```typescript
// lines 311-326
try {
  const nftInfo = await nftGetInfo(key);
  if (nftInfo && nftInfo.success && nftInfo.nft_info && nftInfo.nft_info.data_uris) {
    if ('royalty_percentage' in nftInfo.nft_info) {
      result.royaltyPercentage = parseRoyaltyPercentage(nftInfo.nft_info.royalty_percentage);
    }
  }
} catch {
  // NFT type has already been resolved from offer data; metadata is best effort.
}
```

The override only fires when `nftInfo.success === true`. When the NFT is not in the user's local wallet (the common case for a buy offer), the daemon returns `success: false`, the override is skipped, and the dapp-supplied value stands. This is explicitly confirmed by the codebase's own test:

```typescript
// parseCommandDisplay.test.ts line 414-416
mockNftGetInfo.mockResolvedValue({ success: false });
// result: amountWithRoyalties computed from driver_dict royalty_percentage: '250'
```

`formatAmountWithRoyalties` then computes the displayed total:

```typescript
// lines 364-368
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

This `amountWithRoyalties` value is rendered in `Confirm.tsx` as **"Total Amount with Royalties"** — the primary financial figure the user sees before clicking Approve in the WalletConnect dialog.

---

### Impact Explanation

A malicious dapp sends `chia_wallet.create_offer_for_ids` with a `driver_dict` containing `royalty_percentage: 0` for an NFT that actually carries a 10% on-chain royalty. Because `nftGetInfo` returns `success: false` (NFT not in local wallet), the GUI displays "Total Amount with Royalties: 1 XCH" in the Confirm dialog. The user approves believing their total obligation is 1 XCH. When the offer is accepted on-chain, the NFT's puzzle enforces the actual 10% royalty, and the buyer's wallet is debited 1.1 XCH — 10% more than the approved display showed. This is a direct, concrete accounting discrepancy between what the user approved and what they spend, fitting the High impact category: *"unsafe trust of WalletConnect state that causes a user to approve the wrong amount."*

---

### Likelihood Explanation

Any WalletConnect dapp that has been granted the `chia_wallet.create_offer_for_ids` permission (a standard NFT-marketplace permission) can trigger this. No additional privileges are required. The condition that makes the override fail (`nftGetInfo` returning `success: false`) is the normal state for any NFT the user does not currently own — i.e., every buy-side offer. The attack is silent and requires no user interaction beyond the normal approval flow.

---

### Recommendation

Decouple the royalty percentage override from the `nftInfo.success` / `data_uris` gate. Always attempt to fetch and apply the on-chain `royalty_percentage` independently of whether `data_uris` is present. If `nftGetInfo` fails or returns `success: false` for an NFT involved in a `create_offer_for_ids` command, the GUI should either refuse to display a royalty-adjusted total or display a warning that the royalty could not be verified on-chain, rather than silently trusting the dapp-supplied `driver_dict` value.

---

### Proof of Concept

1. A dapp with `chia_wallet.create_offer_for_ids` permission sends:
   ```json
   {
     "offer": { "1": "-1000000000000", "<nft_launcher_id>": "1" },
     "driver_dict": {
       "<nft_launcher_id>": {
         "type": "singleton",
         "launcher_id": "0x<nft_launcher_id>",
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
   ```
2. The target NFT has a 10% on-chain royalty (`royalty_percentage = 1000` in basis points).
3. The user does not own the NFT (buy-side offer), so `nftGetInfo` returns `success: false`.
4. `createOfferRoyaltyPercentages` reads `royalty_percentage: 0` from `driver_dict`.
5. `formatAmountWithRoyalties` computes `totalAmount = 1 XCH + 0 = 1 XCH`.
6. `Confirm.tsx` displays **"Total Amount with Royalties: 1 XCH"** and **"Royalties Percentage: 0%"**.
7. User approves. The offer is created and accepted on-chain. The NFT puzzle enforces the actual 10% royalty. The buyer's wallet is debited **1.1 XCH** — 0.1 XCH more than the approved display.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L462-480)
```typescript
  if (command === 'chia_wallet.create_offer_for_ids') {
    if (!params.offer || !isPlainObject(params.offer)) {
      throw new Error('Offer is not valid');
    }

    if (params.driver_dict !== undefined && !isPlainObject(params.driver_dict)) {
      throw new Error('Driver Dict is not valid');
    }

    const walletDelta = createOfferToWalletDelta(params.offer);
    const walletInfos = await getWalletInfos();
    const driverDict = params.driver_dict ?? {};
    const assetKinds = createOfferAssetKinds(walletDelta, walletInfos, driverDict);
    const royaltyPercentages = createOfferRoyaltyPercentages(walletDelta, driverDict);

    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, undefined),
    };
  }
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L409-458)
```typescript
  it('shows the create-offer fungible total with driver-provided NFT creator royalties', async () => {
    const nftLauncherId = '6b6b2a3b4c57c2b4596625583cbede95d081b59d18125fedb6b416a8ee46cfe5';
    mockGetWalletInfos.mockResolvedValue({
      1: { name: 'Chia', type: WalletType.STANDARD_WALLET },
    });
    mockNftGetInfo.mockResolvedValue({
      success: false,
    });

    await expect(
      parseCommandDisplay('chia_wallet.create_offer_for_ids', {
        offer: {
          1: '-1000000000000',
          [nftLauncherId]: '1',
        },
        driver_dict: {
          [nftLauncherId]: {
            type: 'singleton',
            launcher_id: `0x${nftLauncherId}`,
            also: {
              type: 'metadata',
              also: {
                type: 'ownership',
                transfer_program: {
                  type: 'royalty transfer program',
                  royalty_percentage: '250',
                },
              },
            },
          },
        },
      }),
    ).resolves.toMatchObject({
      walletDelta: {
        spending: [
          {
            kind: 'xch',
            amount: '1',
            amountWithRoyalties: '1.025',
          },
        ],
        receiving: [
          {
            kind: 'nft',
            royaltyPercentage: 250,
          },
        ],
      },
    });
  });
```
