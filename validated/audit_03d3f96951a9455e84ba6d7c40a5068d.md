### Title
RCAT Amount Mis-Conversion in NFT Offer Creation Causes 10^9× Token Overspend - (File: packages/gui/src/components/offers/NFTOfferEditor.tsx)

### Summary

`buildOfferRequest` in `NFTOfferEditor.tsx` omits `WalletType.RCAT` from the CAT wallet-type guard, causing it to apply `chiaToMojo` (×10^12) instead of `catToMojo` (×10^3) when a user creates an NFT offer priced in RCAT. The UI displays the user-entered amount correctly, but the on-chain offer is submitted for 10^9 times more RCAT mojos than intended. If the offer is accepted, the user loses up to 10^9× more RCAT than they authorized.

### Finding Description

`NFTOfferTokenSelector.tsx` includes `WalletType.RCAT` wallets as selectable payment options for NFT offers: [1](#0-0) 

When the user selects RCAT and submits, `buildOfferRequest` converts the user-entered amount to mojos: [2](#0-1) 

The condition `[WalletType.CAT, WalletType.CRCAT].includes(...)` does **not** include `WalletType.RCAT`, so the else branch executes `chiaToMojo(tokenAmount)`. `chiaToMojo` multiplies by 10^12 (XCH→mojo), while the correct function `catToMojo` multiplies by 10^3 (CAT→mojo). The resulting mojo amount is 10^9 times larger than intended. [3](#0-2) 

By contrast, the older `getUpdatedOffer` helper in `OfferEditor.tsx` correctly includes `WalletType.RCAT` in the CAT branch: [4](#0-3) 

The balance check in `validateFormData` compares `tokenWalletInfo.spendableBalance` (stored in CAT units via `mojoToCAT`) against the user-entered string — both in CAT units — so it passes even when the user has far more RCAT than the displayed amount: [5](#0-4) 

The spendable balance is set in CAT units for RCAT: [6](#0-5) 

The royalty/total display also uses the raw user-entered string, so the UI consistently shows the intended (small) amount while the actual offer encodes the inflated mojo value: [7](#0-6) 

### Impact Explanation

A user who selects RCAT as the payment token in the NFT offer editor and enters, e.g., `1` RCAT:

- UI displays: **1 RCAT**
- Mojos submitted to the wallet RPC: **1,000,000,000,000** (via `chiaToMojo`) instead of **1,000** (via `catToMojo`)
- Effective on-chain offer price: **1,000,000,000 RCAT**

If the user holds a large RCAT balance (the balance check passes in CAT units), the offer is created and signed. Any counterparty who accepts it receives 1,000,000,000 RCAT from the victim's wallet. This is a direct, irreversible CAT asset loss caused by the display/execution amount mismatch — the user approved what appeared to be a 1 RCAT offer.

This matches: *"Corruption… of… offer… state that causes a user to… display the wrong… amount… or status"* and *"Unauthorized… transfer… affecting… CAT"*.

### Likelihood Explanation

- RCAT is a first-class selectable option in `NFTOfferTokenSelector` — no special steps needed to reach the vulnerable path.
- The bug triggers on every NFT offer creation where RCAT is chosen as the payment asset.
- The catastrophic outcome (offer accepted at inflated price) requires the user to hold a large RCAT balance, but the mis-conversion and display mismatch occur unconditionally.

### Recommendation

Add `WalletType.RCAT` to the wallet-type guard in `buildOfferRequest`:

```typescript
// packages/gui/src/components/offers/NFTOfferEditor.tsx
const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
  ? catToMojo(tokenAmount)
  : chiaToMojo(tokenAmount);
```

This mirrors the correct pattern already used in `getUpdatedOffer` in `OfferEditor.tsx`.

### Proof of Concept

1. User has an RCAT wallet with a balance of, e.g., 2,000,000,000 RCAT (2×10^12 mojos).
2. User opens the NFT Offer Editor → "Buy an NFT" tab.
3. In the **Asset Type** dropdown, selects their RCAT wallet (listed because `NFTOfferTokenSelector` includes `WalletType.RCAT`).
4. Enters `1` in the amount field. UI shows **1 RCAT**; balance check passes (2,000,000,000 ≥ 1).
5. Clicks **Create Offer**. `buildOfferRequest` calls `chiaToMojo("1")` → `1,000,000,000,000` mojos.
6. The wallet RPC receives an offer for **1,000,000,000 RCAT** (not 1 RCAT).
7. A counterparty accepts the offer; the user's wallet transfers 1,000,000,000 RCAT — 10^9× the intended amount. [8](#0-7) [9](#0-8)

### Citations

**File:** packages/gui/src/components/offers/NFTOfferTokenSelector.tsx (L58-73)
```typescript
    const catOptions = wallets
      .filter((wallet: Wallet) => [WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(wallet.type))
      .map((wallet: Wallet) => {
        const cat: CATToken | undefined = catList.find(
          (catItem: CATToken) => catItem.assetId.toLowerCase() === wallet.tail?.toLowerCase(),
        );
        return {
          walletId: wallet.id,
          walletType: wallet.type,
          name: wallet.name,
          symbol: cat?.symbol,
          displayName: wallet.name + (cat?.symbol ? ` (${cat.symbol})` : ''),
          disabled: false,
          tail: wallet.tail,
        };
      });
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L144-148)
```typescript
        case WalletType.CAT:
        case WalletType.RCAT:
          balanceString = mojoToCATLocaleString(walletBalance.spendableBalance, locale);
          balance = mojoToCAT(walletBalance.spendableBalance);
          break;
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L191-198)
```typescript
      ...calculateNFTRoyalties(
        parseFloat(amount || '0'),
        parseFloat(includedMakerFee || '0'),
        convertRoyaltyToPercentage(nft.royaltyPercentage),
        tab,
      ),
      royaltyPercentage,
    };
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L491-534)
```typescript
function buildOfferRequest(params: NFTBuildOfferRequestParams) {
  const { exchangeType, nft, nftLauncherId, tokenWalletInfo, tokenAmount, fee } = params;
  const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
    ? catToMojo(tokenAmount)
    : chiaToMojo(tokenAmount);
  const mojoAmount = exchangeType === NFTOfferExchangeType.NFTForToken ? baseMojoAmount : baseMojoAmount.negated();
  const feeMojoAmount = chiaToMojo(fee);
  const nftAmount = exchangeType === NFTOfferExchangeType.NFTForToken ? -1 : 1;
  const innerAlsoDict = nft.supportsDid
    ? {
        type: 'ownership',
        owner: '()',
        transfer_program: {
          type: 'royalty transfer program',
          launcher_id: `0x${nftLauncherId}`,
          royalty_address: nft.royaltyPuzzleHash,
          royalty_percentage: `${nft.royaltyPercentage}`,
        },
      }
    : undefined;
  const outerAlsoDict = {
    type: 'metadata',
    metadata: nft.chainInfo,
    updater_hash: nft.updaterPuzhash,
    ...(innerAlsoDict ? { also: innerAlsoDict } : undefined),
  };
  const driverDict = {
    [nftLauncherId]: {
      type: 'singleton',
      launcher_id: `0x${nftLauncherId}`,
      launcher_ph: nft.launcherPuzhash,
      also: outerAlsoDict,
    },
  };

  return [
    {
      [nftLauncherId]: nftAmount,
      [tokenWalletInfo.walletId]: mojoAmount,
    },
    exchangeType === NFTOfferExchangeType.TokenForNFT ? driverDict : undefined,
    feeMojoAmount,
  ];
}
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L587-591)
```typescript
    } else if (
      exchangeTypeLocal === NFTOfferExchangeType.TokenForNFT &&
      tokenWalletInfo.spendableBalance?.isLessThan(tokenAmount)
    ) {
      errorDialog(new Error(t`Amount exceeds spendable balance`));
```

**File:** packages/gui/src/components/offers/OfferEditor.tsx (L200-202)
```typescript
    } else if ([WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(walletTypeLocal)) {
      mojoAmount = catToMojo(amount);
    }
```
