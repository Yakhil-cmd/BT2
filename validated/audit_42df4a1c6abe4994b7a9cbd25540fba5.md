The bug is confirmed and real. Here is the analysis:

**The discrepancy is concrete and code-verified:**

`NFTOfferTokenSelector.tsx` line 59 includes `WalletType.RCAT` in `catOptions`: [1](#0-0) 

`NFTOfferEditor.tsx` `buildOfferRequest` line 493 checks only `[WalletType.CAT, WalletType.CRCAT]` — `WalletType.RCAT` is absent, so RCAT falls through to `chiaToMojo`: [2](#0-1) 

The scale difference: `catToMojo` uses `Unit.CAT` (1 CAT = 1,000 mojos, 1e3), `chiaToMojo` uses `Unit.CHIA` (1 XCH = 1,000,000,000 mojos, 1e9). The ratio is **1e6x**, not 1e9x as the question states — but the direction is correct and the bug is real.

For contrast, `OfferEditor.tsx` (the non-NFT offer path) correctly includes `WalletType.RCAT` in the `catToMojo` branch: [3](#0-2) 

---

### Title
RCAT mojo conversion uses `chiaToMojo` instead of `catToMojo` in NFT offer creation, causing 1e6x amount inflation — (`packages/gui/src/components/offers/NFTOfferEditor.tsx`)

### Summary
`buildOfferRequest` in `NFTOfferEditor.tsx` omits `WalletType.RCAT` from the `catToMojo` branch. Because `NFTOfferTokenSelector` presents RCAT wallets as valid selections, a user who selects an RCAT wallet and enters any token amount will have that amount converted at the XCH scale (1e9 mojos/unit) rather than the CAT scale (1e3 mojos/unit), inflating the committed mojo amount by 1,000,000x.

### Finding Description
In `NFTOfferEditor.tsx`, `buildOfferRequest` determines the mojo conversion function by checking:

```typescript
const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
  ? catToMojo(tokenAmount)
  : chiaToMojo(tokenAmount);
```

`WalletType.RCAT` is not in the array, so it falls to `chiaToMojo`. Meanwhile, `NFTOfferTokenSelector` explicitly includes RCAT wallets in the dropdown:

```typescript
.filter((wallet: Wallet) => [WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(wallet.type))
```

The non-NFT offer path (`OfferEditor.tsx` line 200) correctly handles RCAT with `catToMojo`. This is a localized omission in the NFT-specific editor only.

### Impact Explanation
- User enters `0.001` RCAT → `chiaToMojo(0.001)` = 1,000,000 mojos → offer commits **1,000 RCAT** (1,000,000 mojos ÷ 1e3 mojos/RCAT)
- User intended to commit **0.001 RCAT** (1 mojo)
- If the user's RCAT wallet has sufficient balance, the offer is created and broadcast with 1,000,000x the intended mojo amount
- A counterparty who accepts the offer receives 1,000,000x more RCAT than the user intended to trade — direct, irreversible asset loss

This fits the High impact category: the GUI causes the user to commit the wrong amount for an asset in an offer.

### Likelihood Explanation
RCAT (Restricted CAT) wallets are a supported wallet type surfaced in the NFT offer token selector. Any user with an RCAT wallet who uses the NFT offer editor is affected. No attacker action is required beyond the user performing a normal workflow. The bug is triggered deterministically on every RCAT NFT offer creation.

### Recommendation
Add `WalletType.RCAT` to the `catToMojo` branch in `buildOfferRequest`:

```typescript
const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
  ? catToMojo(tokenAmount)
  : chiaToMojo(tokenAmount);
```

This matches the pattern already used correctly in `OfferEditor.tsx` line 200 and `utils.ts` line 155.

### Proof of Concept
1. Create an RCAT wallet in the Chia GUI.
2. Open the NFT offer editor for any NFT.
3. Select the RCAT wallet from the token selector dropdown.
4. Enter `0.001` as the token amount.
5. Observe: `buildOfferRequest` calls `chiaToMojo('0.001')` = 1,000,000 mojos.
6. Correct value: `catToMojo('0.001')` = 1 mojo.
7. If the wallet holds ≥ 1,000,000 mojos of RCAT, the offer is created committing 1,000 RCAT instead of 0.001 RCAT.
8. Differential test: call `buildOfferRequest` with `walletType=WalletType.RCAT` vs `walletType=WalletType.CAT` for `tokenAmount='1'`; assert both return the same mojo amount (1,000 mojos). Currently they differ by 1e6.

### Citations

**File:** packages/gui/src/components/offers/NFTOfferTokenSelector.tsx (L58-59)
```typescript
    const catOptions = wallets
      .filter((wallet: Wallet) => [WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(wallet.type))
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L493-495)
```typescript
  const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
    ? catToMojo(tokenAmount)
    : chiaToMojo(tokenAmount);
```

**File:** packages/gui/src/components/offers/OfferEditor.tsx (L200-201)
```typescript
    } else if ([WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(walletTypeLocal)) {
      mojoAmount = catToMojo(amount);
```
