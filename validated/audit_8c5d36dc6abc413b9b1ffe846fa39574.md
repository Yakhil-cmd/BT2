The code confirms the bug is real. Let me lay out the exact findings:

**In `NFTOfferTokenSelector.tsx` line 59:** [1](#0-0) 

`WalletType.RCAT` is included in the filter, so RCAT wallets appear as selectable options.

**In `NFTOfferEditor.tsx` line 493:** [2](#0-1) 

`buildOfferRequest` only checks `[WalletType.CAT, WalletType.CRCAT]` — `WalletType.RCAT` is absent. Any RCAT selection falls through to `chiaToMojo`.

**The balance display for RCAT is correctly handled** (line 145–147 uses `mojoToCAT`/`mojoToCATLocaleString`), so the spendable balance check passes in CAT units, but the offer amount is then computed with `chiaToMojo` — a factor of 1e12 vs 1e3, i.e., a **1,000,000,000× over-conversion**, not 1,000× as the question states. [3](#0-2) 

**No confirmation dialog exists** between form submission and `createOfferForIds` being called — `handleSubmit` fires the RPC directly. [4](#0-3) 

---

### Title
RCAT Amount Unit-Conversion Mismatch in NFT Offer Editor Causes Billion-Fold Mojo Over-Commitment — (`packages/gui/src/components/offers/NFTOfferEditor.tsx`)

### Summary
`NFTOfferTokenSelector` exposes RCAT wallets as valid offer token choices, but `buildOfferRequest` omits `WalletType.RCAT` from its CAT-conversion branch, silently applying `chiaToMojo` (1 XCH = 1e12 mojos) instead of `catToMojo` (1 CAT = 1e3 mojos) to the user-entered RCAT amount.

### Finding Description
`NFTOfferTokenSelector` filters wallets with `[WalletType.CAT, WalletType.RCAT, WalletType.CRCAT]` (line 59), making RCAT wallets selectable. `buildOfferRequest` (line 493) checks only `[WalletType.CAT, WalletType.CRCAT]` for the `catToMojo` path; `WalletType.RCAT` is unhandled and falls through to `chiaToMojo`. The spendable-balance guard (line 587–591) compares the user-entered amount against a balance already expressed in CAT units (via `mojoToCAT`), so it passes for any user with ≥ N RCAT tokens. The resulting offer is submitted directly to `createOfferForIds` with no intermediate confirmation showing the raw mojo value.

### Impact Explanation
A user with an RCAT wallet who enters `N` tokens in the NFT offer editor will have an offer created committing `N × 1e12` mojos of RCAT instead of `N × 1e3` mojos — a 1,000,000,000× over-commitment. If the user holds sufficient RCAT balance and the offer is accepted, they lose approximately one billion times more RCAT than intended. This is direct, irreversible asset loss through a production offer workflow.

### Likelihood Explanation
RCAT (Restricted CAT) is a supported wallet type in the Chia stack. Any user who has an RCAT wallet and uses the NFT offer editor is exposed. No attacker involvement is required; the user triggers the bug through normal UI interaction. The balance guard does not prevent the over-committed offer from being created and shared.

### Recommendation
Add `WalletType.RCAT` to the `catToMojo` branch in `buildOfferRequest`:

```ts
const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.CRCAT, WalletType.RCAT].includes(tokenWalletInfo.walletType)
  ? catToMojo(tokenAmount)
  : chiaToMojo(tokenAmount);
```

### Proof of Concept
Unit-test `buildOfferRequest` with `walletType = WalletType.RCAT` and `tokenAmount = '1'`:
- **Actual (buggy):** `mojoAmount = chiaToMojo('1') = 1_000_000_000_000`
- **Expected:** `mojoAmount = catToMojo('1') = 1_000`

The 1e9× discrepancy is directly observable without any blockchain interaction.

### Citations

**File:** packages/gui/src/components/offers/NFTOfferTokenSelector.tsx (L58-60)
```typescript
    const catOptions = wallets
      .filter((wallet: Wallet) => [WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(wallet.type))
      .map((wallet: Wallet) => {
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L144-148)
```typescript
        case WalletType.CAT:
        case WalletType.RCAT:
          balanceString = mojoToCATLocaleString(walletBalance.spendableBalance, locale);
          balance = mojoToCAT(walletBalance.spendableBalance);
          break;
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L493-495)
```typescript
  const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
    ? catToMojo(tokenAmount)
    : chiaToMojo(tokenAmount);
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L647-663)
```typescript
    const [offer, driverDict, feeInMojos] = buildOfferRequest({
      exchangeType: exchangeTypeLocal,
      nft: offerNFT,
      nftLauncherId: launcherIdLocal,
      tokenWalletInfo,
      tokenAmount,
      fee,
    });

    try {
      const response = await createOfferForIds({
        offer,
        fee: feeInMojos,
        driverDict,
        validateOnly: false,
        disableJSONFormatting: true,
      }).unwrap();
```
