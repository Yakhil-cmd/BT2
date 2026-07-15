### Title
Silent Failure in Offer Cancellation Corrupts Conflict-Resolution State, Bypassing Required Cancellation Gate - (File: packages/gui/src/components/offers2/CancelOfferList.tsx)

### Summary
In `CancelOfferList.tsx`, the `cancelOffer` RTK Query mutation is called without `.unwrap()`. In RTK Query, omitting `.unwrap()` means a failed mutation resolves silently (returning `{ error }`) instead of throwing. As a result, `onOfferCanceled` is unconditionally called after `cancelOffer`, regardless of whether the backend cancellation actually succeeded. This corrupts the offer-conflict-resolution dialog's state, causing it to auto-close and grant the user permission to proceed with creating a new offer — even when the required conflicting offer was never actually canceled.

### Finding Description

In `handleCancelOffer` inside `CancelOfferList.tsx`:

```typescript
await cancelOffer({ tradeId, secure, fee });
onOfferCanceled(tradeId, secure, fee);   // called unconditionally
``` [1](#0-0) 

RTK Query mutations called without `.unwrap()` do not throw on failure — they resolve with `{ error: ... }`. The `await` completes normally, and `onOfferCanceled` fires regardless of the actual backend result.

`CancelOfferList` is embedded in `OfferEditorCancelConflictingOffersDialog`, which is shown when a new offer conflicts with existing open offers. The `onOfferCanceled` prop is wired to `onCancelOffer1`, which removes the offer from the `assetsToUnlock` state array and recalculates spendable amounts: [2](#0-1) 

The dialog's "Proceed" button is gated on `offersRequiredToBeCanceled.length > 0`, and the dialog has an `autoClose` prop that fires when all required offers appear cleared:

```typescript
const areOffersAllCleared = useMemo(() => {
  if (offersRequiredToBeCanceled.length + offersBetterToBeCanceled.length > 0) {
    return undefined;
  }
  return 'confirm';
}, [...]);
``` [3](#0-2) 

Because `onCancelOffer1` is called even on a failed cancellation, `assetsToUnlock` is updated to remove the offer from the required list. When the last required offer is "removed" this way, `areOffersAllCleared` becomes `'confirm'`, the dialog auto-closes, and `CreateOfferBuilder` receives `confirmedToProceed = true`: [4](#0-3) 

`createOfferForIds` is then called to create the new offer while the conflicting offer is still active on the backend.

A second instance of the same pattern exists in `OfferManager.tsx` in the `relistOffer` function, where `cancelOffer` is also called without `.unwrap()` before navigating the user to the offer builder: [5](#0-4) 

### Impact Explanation

The required cancellation gate — the only client-side guard preventing the user from creating a new offer while a conflicting offer is still active — is bypassed. The user's UI shows the conflicting offer as canceled when it is not. The dialog auto-closes and the user proceeds to `createOfferForIds`. If the backend permits the new offer to be created (the conflict check is client-side), the user ends up with two simultaneously active offers locking the same assets. A concrete race condition: a counterparty accepts Offer A at the moment the user tries to cancel it; the cancellation fails silently; the UI shows Offer A as canceled; the user creates Offer B for the same assets they no longer hold. This is offer-state corruption causing the user to approve a new offer under false pretenses about their spendable balance and active offer set.

### Likelihood Explanation

The failure condition is reachable without any privileged access. It triggers whenever `cancelOffer` returns an error — network interruption, wallet not synced, offer already accepted by a counterparty, or any backend rejection. The "offer already accepted" race is particularly realistic in active markets. No attacker capability beyond being a counterparty who accepts an offer is required.

### Recommendation

Replace the fire-and-forget call with `.unwrap()` so that errors propagate and `onOfferCanceled` is only called on confirmed success:

```typescript
// CancelOfferList.tsx – handleCancelOffer
try {
  await cancelOffer({ tradeId, secure, fee }).unwrap();
  onOfferCanceled(tradeId, secure, fee);
} catch (error) {
  showError(error); // surface the failure to the user
}
```

Apply the same fix to `relistOffer` in `OfferManager.tsx` (line 106).

### Proof of Concept

1. User holds 10 XCH and has Offer A open: offering 10 XCH for 100 CAT.
2. User attempts to create Offer B: offering 10 XCH for 200 CAT. The GUI detects the conflict and opens `OfferEditorCancelConflictingOffersDialog` requiring Offer A to be canceled first.
3. User clicks "Cancel" on Offer A in the dialog.
4. Simultaneously, a counterparty accepts Offer A on-chain. The 10 XCH leave the user's wallet.
5. `cancelOffer({ tradeId: A, secure, fee })` is dispatched. The backend rejects it (offer already spent). RTK Query resolves the promise with `{ error }` — no exception is thrown.
6. `onOfferCanceled(tradeId, ...)` fires unconditionally. `onCancelOffer1` removes Offer A from `assetsToUnlock`.
7. `offersRequiredToBeCanceled` becomes empty → `areOffersAllCleared = 'confirm'` → dialog auto-closes with `confirmedToProceed = true`.
8. `CreateOfferBuilder.handleSubmit` calls `createOfferForIds` for Offer B (10 XCH for 200 CAT).
9. The user's wallet now has 0 XCH (already transferred via Offer A), but the GUI presented the offer creation flow as valid. The user is operating on a corrupted view of their offer state and spendable balance. [6](#0-5) [7](#0-6) [3](#0-2) [4](#0-3)

### Citations

**File:** packages/gui/src/components/offers2/CancelOfferList.tsx (L53-63)
```typescript
    async function handleCancelOffer(tradeId: string, canCancelWithTransaction: boolean) {
      const [cancelConfirmed, cancellationOptions] = await openDialog(
        <ConfirmOfferCancellation canCancelWithTransaction={canCancelWithTransaction} />,
      );

      if (cancelConfirmed === true) {
        const secure = canCancelWithTransaction ? cancellationOptions.cancelWithTransaction : false;
        const fee = canCancelWithTransaction ? cancellationOptions.cancellationFee : 0;
        await cancelOffer({ tradeId, secure, fee });
        onOfferCanceled(tradeId, secure, fee);
      }
```

**File:** packages/gui/src/components/offers2/OfferEditorCancelConflictingOffersDialog.tsx (L83-201)
```typescript
  const onCancelOffer1 = useCallback(
    (tradeId: string, _secure: boolean, _fee: BigNumber) => {
      let isAssetsToUnlockUpdated = false;
      let isAssetsBetterUnlockUpdated = false;

      const assetsToUnlockUpdated: AssetStatusForOffer[] = [];
      const assetsBetterUnlockedAdded: AssetStatusForOffer[] = [];
      let lockedAssetsFoundIndex = -1;
      let lockedAssets: PendingAsset[] = [];

      for (let i = 0; i < assetsToUnlock.length; i++) {
        const atu = { ...assetsToUnlock[i] };
        const newRelevantOffers = [];
        for (let k = 0; k < atu.relevantOffers.length; k++) {
          const ro = atu.relevantOffers[k];
          if (ro.tradeId === tradeId) {
            const relevantOfferNotFoundYet = lockedAssetsFoundIndex === -1;
            // Assuming that an offer is unique by its tradeId.
            // When canceled offer is already identified by tradeId in previous loop,
            // no need to investigate locked assets anymore because we already know what they are
            // in previous loop.
            if (relevantOfferNotFoundYet) {
              // The code in this block only runs 0 or 1 time for the loop indexed by `i`
              lockedAssetsFoundIndex = i;
              lockedAssets = resolvePendingAssets(ro);

              // Modify values in assetsToUnlockUpdated before this loop.
              for (let p = 0; p < lockedAssetsFoundIndex; p++) {
                const assetToModify = assetsToUnlockUpdated[p];
                const newSpendableAmount = getSpendableAmountUponUnlockingAssets(assetToModify, lockedAssets);
                if (!newSpendableAmount.eq(assetToModify.spendableAmount)) {
                  isAssetsToUnlockUpdated = true;
                  assetsToUnlockUpdated[p] = { ...assetToModify, spendableAmount: newSpendableAmount };
                }

                if (assetsToUnlockUpdated[p].spendableAmount.gte(assetsToUnlockUpdated[p].spendingAmount)) {
                  isAssetsToUnlockUpdated = true;
                  assetsToUnlockUpdated[p] = {
                    ...assetsToUnlockUpdated[p],
                    status: 'alsoUsedInNewOfferWithoutConflict',
                  };
                }
              }
            }
          } else {
            newRelevantOffers.push(ro);
          }
        }

        const wasOfferRemoved = newRelevantOffers.length !== atu.relevantOffers.length;
        // Update relevant offers (Canceled offer is removed from original array)
        atu.relevantOffers = newRelevantOffers;

        // Modify spendableAmount in atc
        atu.spendableAmount = getSpendableAmountUponUnlockingAssets(atu, lockedAssets);
        const notRequiredToCancelAnymore = atu.spendableAmount.gte(atu.spendingAmount);

        if (notRequiredToCancelAnymore) {
          // If spending amount is less than or equal to spendable amount for assetType/assetId,
          // then the offer for the asset is not required to cancel anymore.
          isAssetsToUnlockUpdated = true;
          if (newRelevantOffers.length > 0) {
            isAssetsBetterUnlockUpdated = true;
            // The priority of canceling the offer goes down.
            assetsBetterUnlockedAdded.push({
              ...atu,
              status: 'alsoUsedInNewOfferWithoutConflict',
            });
          }
        } else if (wasOfferRemoved) {
          isAssetsToUnlockUpdated = true;
          assetsToUnlockUpdated.push(atu); // Will re-render since otc !== offersToCancel[i]. Remember that otc = {...offersToCancel[i]}.
        } else {
          assetsToUnlockUpdated.push(assetsToUnlock[i]); // Will NOT re-render since object keeps the same reference
        }
      }

      // Check whether `assetsBetterUnlocked` contains cancelling offer
      const newAssetsBetterUnlocked: AssetStatusForOffer[] = [];
      for (let i = 0; i < assetsBetterUnlocked.length; i++) {
        const abu = assetsBetterUnlocked[i];
        const newRelevantOffers: OfferTradeRecordFormatted[] = [];
        for (let k = 0; k < abu.relevantOffers.length; k++) {
          const ro = abu.relevantOffers[k];
          if (ro.tradeId === tradeId) {
            isAssetsBetterUnlockUpdated = true;
          } else {
            newRelevantOffers.push(ro);
          }
        }

        // When one of the relevantOffers is deleted, reflect it
        if (newRelevantOffers.length !== abu.relevantOffers.length) {
          if (newRelevantOffers.length > 0) {
            isAssetsBetterUnlockUpdated = true;
            // When newRelevantOffers.length === 0, the abu will be technically deleted by not pushing it into `newAssetsBetterUnlocked`
            newAssetsBetterUnlocked.push({
              ...abu,
              relevantOffers: newRelevantOffers,
            });
          }
        } else {
          newAssetsBetterUnlocked.push(abu);
        }
      }

      // Avoiding unnecessary re-render
      if (isAssetsToUnlockUpdated) {
        setAssetsToUnlock(assetsToUnlockUpdated);
      }
      if (isAssetsBetterUnlockUpdated) {
        if (assetsBetterUnlockedAdded.length > 0) {
          setAssetsBetterUnlocked([...assetsBetterUnlockedAdded, ...newAssetsBetterUnlocked]);
        } else {
          setAssetsBetterUnlocked(newAssetsBetterUnlocked);
        }
      }
    },
    [assetsToUnlock, setAssetsToUnlock, assetsBetterUnlocked, setAssetsBetterUnlocked],
```

**File:** packages/gui/src/components/offers2/OfferEditorCancelConflictingOffersDialog.tsx (L310-316)
```typescript
        <CancelOfferList
          offers={offersRequiredToBeCanceled}
          title={<Trans>Open offers required to be canceled to refill spendable amount</Trans>}
          onOfferCanceled={onCancelOffer1}
          allowSecureCancelling={allowSecureCancelling}
        />
      </Flex>
```

**File:** packages/gui/src/components/offers2/OfferEditorCancelConflictingOffersDialog.tsx (L350-366)
```typescript
  const areOffersAllCleared = useMemo(() => {
    if (offersRequiredToBeCanceled.length + offersBetterToBeCanceled.length > 0) {
      return undefined;
    }
    return 'confirm';
  }, [offersRequiredToBeCanceled.length, offersBetterToBeCanceled.length]);

  return (
    <ConfirmDialog
      title={<Trans>Remove Conflicting Offer</Trans>}
      confirmTitle={<Trans>Proceed</Trans>}
      confirmColor="primary"
      cancelTitle={<Trans>Cancel</Trans>}
      fullWidth
      maxWidth="md"
      disableConfirmButton={offersRequiredToBeCanceled.length > 0}
      autoClose={areOffersAllCleared}
```

**File:** packages/gui/src/components/offers2/CreateOfferBuilder.tsx (L120-134)
```typescript
        const confirmedToProceed = await openDialog(dialog);
        if (!confirmedToProceed) {
          return;
        }
      }

      try {
        const response = await createOfferForIds({
          offer: localOffer.walletIdsAndAmounts,
          fee: localOffer.feeInMojos,
          driver_dict: localOffer.driverDict, // snake case is intentional since disableJSONFormatting is true
          validate_only: localOffer.validateOnly, // snake case is intentional since disableJSONFormatting is true
          disableJSONFormatting: true, // true to avoid converting driver_dict keys/values to camel case. The camel case conversion breaks the driver_dict and causes offer creation to fail.
          max_time: expirationTimeForOffer,
        }).unwrap();
```

**File:** packages/gui/src/components/offers/OfferManager.tsx (L105-119)
```typescript
    async function relistOffer(row: OfferTradeRecord, tradeId: string) {
      await cancelOffer({ tradeId, secure: false, fee: 0 });
      const newSummary = { ...row.summary };
      // swap offering and requested
      newSummary.offered = row.summary.requested;
      newSummary.requested = row.summary.offered;
      const offer = offerToOfferBuilderData(newSummary, false, '');
      navigate('/dashboard/offers/builder', {
        state: {
          referrerPath: '/dashboard/offers',
          isCounterOffer: false,
          offer,
        },
        replace: true,
      });
```
