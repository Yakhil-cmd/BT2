Let me examine the relevant code to verify the claims.

The code confirms the inconsistency is real. Here is the analysis:

**Line 59** — `NFTOfferTokenSelector` includes `WalletType.RCAT` in `catOptions`: [1](#0-0) 

**Lines 144–148** — `spendableBalanceString` correctly treats RCAT like CAT, using `mojoToCATLocaleString` and `mojoToCAT` for balance display: [2](#0-1) 

**Line 493** — `buildOfferRequest` checks only `[WalletType.CAT, WalletType.CRCAT]`, omitting `WalletType.RCAT`, so RCAT falls through to `chiaToMojo`: [3](#0-2) 

**Line 589** — The balance guard compares `spendableBalance` (set in CAT units for RCAT) against the user-entered `tokenAmount` (also in CAT units), so the guard passes correctly but does not catch the downstream conversion error: [4](#0-3) 

---

### Title
RCAT mojo conversion inconsistency in `buildOfferRequest` causes 1e9x offer amount — (`packages/gui/src/components/offers/NFTOfferEditor.tsx`)

### Summary
`buildOfferRequest` omits `WalletType.RCAT` from the CAT branch, causing it to apply `chiaToMojo` (1 unit = 1,000,000,000,000 mojos) instead of `catToMojo` (1 unit = 1,000 mojos) for RCAT amounts. The balance display and validation correctly use CAT units for RCAT, so the balance check passes, but the submitted offer encodes a mojo amount 1,000,000,000× larger than intended.

### Finding Description
In `NFTOfferConditionalsPanel`, `spendableBalanceString` (lines 144–148) handles `WalletType.RCAT` identically to `WalletType.CAT`: it calls `mojoToCATLocaleString` and `mojoToCAT`, storing the balance in CAT units. The balance guard at line 589 compares this CAT-unit balance against the user-entered amount — also in CAT units — so it passes correctly.

However, `buildOfferRequest` at line 493 only checks `[WalletType.CAT, WalletType.CRCAT]`. `WalletType.RCAT` is absent, so it falls through to `chiaToMojo(tokenAmount)`. For a user entering `50` RCAT:

- Intended: `catToMojo(50)` = 50,000 mojos
- Actual: `chiaToMojo(50)` = 50,000,000,000,000 mojos (1e9× larger)

### Impact Explanation
If a user holds a large RCAT balance (e.g., 100,000 RCAT = 100,000,000,000 mojos), enters `50` (intending to offer 50 RCAT), the balance check passes (100,000 ≥ 50), and the offer is submitted encoding 50 trillion mojos of RCAT instead of 50,000 mojos. If the wallet has sufficient mojos, the offer is created and can be accepted by a counterparty, resulting in the user losing ~1,000,000,000× more RCAT than intended — direct asset loss.

### Likelihood Explanation
RCAT wallets are selectable in the UI via `NFTOfferTokenSelector`. Any user with an RCAT wallet who uses the NFT offer editor to buy an NFT is exposed. The bug is triggered by normal user interaction with no special preconditions beyond having an RCAT wallet.

### Recommendation
Add `WalletType.RCAT` to the CAT branch in `buildOfferRequest`:

```ts
// line 493 — fix
const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.CRCAT, WalletType.RCAT].includes(tokenWalletInfo.walletType)
  ? catToMojo(tokenAmount)
  : chiaToMojo(tokenAmount);
```

### Proof of Concept
1. Create an RCAT wallet with a balance of ≥ 100 RCAT.
2. Open the NFT offer editor in "Buy an NFT" mode.
3. Select the RCAT wallet as the token type.
4. Observe the spendable balance displayed in CAT units (e.g., "100").
5. Enter `50` as the amount — balance check passes.
6. Submit the offer and inspect the RPC payload: the mojo amount for the RCAT wallet ID will be `chiaToMojo(50)` = `50000000000000` instead of `catToMojo(50)` = `50000`.

### Citations

**File:** packages/gui/src/components/offers/NFTOfferTokenSelector.tsx (L58-59)
```typescript
    const catOptions = wallets
      .filter((wallet: Wallet) => [WalletType.CAT, WalletType.RCAT, WalletType.CRCAT].includes(wallet.type))
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

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L587-591)
```typescript
    } else if (
      exchangeTypeLocal === NFTOfferExchangeType.TokenForNFT &&
      tokenWalletInfo.spendableBalance?.isLessThan(tokenAmount)
    ) {
      errorDialog(new Error(t`Amount exceeds spendable balance`));
```
