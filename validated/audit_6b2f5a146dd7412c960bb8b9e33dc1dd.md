### Title
Stale Amount Value Causes Wrong Mojo Conversion When Switching Token Type in NFT Offer Editor - (File: packages/gui/src/components/offers/NFTOfferEditor.tsx)

### Summary
In the NFT Offer Editor, when a user switches the payment token type (e.g., from XCH to a CAT or vice versa), the previously entered `tokenAmount` string is not cleared. Because XCH and CAT use different decimal scales (1 XCH = 10¹² mojos; 1 CAT = 10³ mojos), the same numeric string is silently reinterpreted under the new unit, causing the offer to be submitted with an amount that is up to 10⁹× larger or smaller than the user intended.

### Finding Description

`NFTOfferEditor.tsx` initialises the form with `tokenWalletInfo` (defaulting to XCH) and a separate `tokenAmount` string field. The `NFTOfferTokenSelector` dropdown lets the user switch between XCH and any CAT wallet. Its `onChange` handler calls `handleTokenSelectionChanged`, which only updates `tokenWalletInfo` and never touches `tokenAmount`:

```js
function handleTokenSelectionChanged(walletId, walletType, symbol, name) {
  methods.setValue('tokenWalletInfo', { walletId, walletType, symbol, name });
  // tokenAmount is NOT reset
}
``` [1](#0-0) 

At submission, `buildOfferRequest` branches on `tokenWalletInfo.walletType` to choose the mojo conversion:

```js
const baseMojoAmount = [WalletType.CAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
  ? catToMojo(tokenAmount)   // 1 CAT  → 1 000 mojos
  : chiaToMojo(tokenAmount); // 1 XCH  → 1 000 000 000 000 mojos
``` [2](#0-1) 

The decimal scales are defined globally and differ by 10⁹: [3](#0-2) 

The pre-submission balance guard compares `tokenWalletInfo.spendableBalance` (in human-readable CAT/XCH units) against the raw `tokenAmount` string, so it does not detect the unit mismatch and does not block submission: [4](#0-3) 

### Impact Explanation

A user who types `1` while XCH is selected (intending 1 XCH = 10¹² mojos), then switches to a CAT token without clearing the field, will submit an offer for 1 CAT = 1 000 mojos — a 10⁹× reduction in value. The reverse path (CAT → XCH) inflates the amount by the same factor. There is no confirmation dialog between "Create Offer" and the RPC call; the offer is signed and broadcast immediately. If a counterparty accepts the offer, the user suffers direct, irreversible asset loss or unintended asset gain.

This matches the allowed High impact: *"Corruption … of … offer … state that causes a user to … sign, send … the wrong … amount."*

### Likelihood Explanation

The NFT Offer Editor is a standard user-facing flow. Switching the payment token type after entering an amount is a natural editing action (e.g., changing one's mind from XCH to a stablecoin CAT). The `Amount` component does display a mojo helper text that would update, but the numeric field itself is unchanged and the label still reads "1", making the discrepancy easy to miss — especially since the mojo count is shown in small helper text below the input. No attacker interaction is required; the user's own editing sequence triggers the bug.

### Recommendation

Reset `tokenAmount` to `''` inside `handleTokenSelectionChanged` whenever the wallet type changes:

```js
function handleTokenSelectionChanged(walletId, walletType, symbol, name) {
  methods.setValue('tokenWalletInfo', { walletId, walletType, symbol, name });
  if (walletType !== methods.getValues('tokenWalletInfo').walletType) {
    methods.setValue('tokenAmount', '');
  }
}
```

Alternatively, display a prominent unit-change warning and require the user to re-enter the amount, mirroring the pattern used in `OfferEditorConditionsPanel` where `handleAssetChange` could similarly be hardened. [5](#0-4) 

### Proof of Concept

1. Open the NFT Offer Editor in "Buy an NFT" mode.
2. In the "You will offer" section, the token selector defaults to XCH.
3. Type `1` in the Amount field. The helper text shows `1,000,000,000,000 mojos`.
4. Open the token selector dropdown and choose any CAT wallet (e.g., a stablecoin).
5. Observe: the Amount field still shows `1`; the helper text now shows `1,000 mojos` — a 10⁹× reduction.
6. Click **Create Offer** without modifying the amount.
7. `buildOfferRequest` calls `catToMojo("1")` = 1 000 mojos and submits the offer. The user intended to offer 1 XCH (≈ $30) but the offer is for 1 CAT (≈ $0.000001). [6](#0-5) [7](#0-6)

### Citations

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L225-243)
```typescript
          <Amount
            id={`${tab}-amount}`}
            key={`${tab}-amount}`}
            variant="filled"
            name="tokenAmount"
            color="secondary"
            disabled={disabled}
            label={<Trans>Amount</Trans>}
            defaultValue={amount}
            symbol={tokenWalletInfo.symbol ?? ''}
            onChange={handleAmountChange}
            onFocus={() => setAmountFocused(true)}
            onBlur={() => setAmountFocused(false)}
            showAmountInMojos
            InputLabelProps={{ shrink: shrinkAmount }}
            autoFocus
            required
            fullWidth
          />
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L256-263)
```typescript
      <Grid xs={6} item>
        <NFTOfferTokenSelector
          selectedWalletId={tokenWalletInfo.walletId}
          id="tokenWalletId"
          onChange={(selection) =>
            handleTokenSelectionChanged(selection.walletId, selection.walletType, selection.symbol, selection.name)
          }
        />
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L281-283)
```typescript
  function handleTokenSelectionChanged(walletId: number, walletType: WalletType, symbol?: string, name?: string) {
    methods.setValue('tokenWalletInfo', { walletId, walletType, symbol, name });
  }
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L491-496)
```typescript
function buildOfferRequest(params: NFTBuildOfferRequestParams) {
  const { exchangeType, nft, nftLauncherId, tokenWalletInfo, tokenAmount, fee } = params;
  const baseMojoAmount: BigNumber = [WalletType.CAT, WalletType.CRCAT].includes(tokenWalletInfo.walletType)
    ? catToMojo(tokenAmount)
    : chiaToMojo(tokenAmount);
  const mojoAmount = exchangeType === NFTOfferExchangeType.NFTForToken ? baseMojoAmount : baseMojoAmount.negated();
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L587-591)
```typescript
    } else if (
      exchangeTypeLocal === NFTOfferExchangeType.TokenForNFT &&
      tokenWalletInfo.spendableBalance?.isLessThan(tokenAmount)
    ) {
      errorDialog(new Error(t`Amount exceeds spendable balance`));
```

**File:** packages/gui/src/electron/constants/UnitValue.ts (L1-7)
```typescript
import Unit from './Unit';

const UnitValue = {
  [Unit.CHIA]: 1,
  [Unit.MOJO]: 1 / 1e12,
  [Unit.CAT]: 1 / 1e9,
};
```

**File:** packages/gui/src/components/offers/OfferEditorConditionsPanel.tsx (L88-97)
```typescript
  function handleAssetChange(namePrefixLocal: string, selectedWalletId: number, selectedWalletType: WalletType) {
    const rowLocal: OfferEditorRowData = getValues(namePrefixLocal);

    rowLocal.assetWalletId = selectedWalletId;
    rowLocal.walletType = selectedWalletType;
    rowLocal.spendableBalanceString = spendableBalanceString;
    rowLocal.spendableBalance = walletBalance ? new BigNumber(walletBalance.spendableBalance) : new BigNumber(0);

    updateRow(rowLocal);
  }
```
