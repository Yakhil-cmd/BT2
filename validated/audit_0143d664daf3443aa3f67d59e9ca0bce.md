Let me check the `useAcceptOfferHook` and the `canAccept`/`disableAccept` guards more carefully. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx (L44-48)
```typescript
  const canAdd =
    !fields.length && // If there is not already a fee field
    ((state === undefined && !viewer) || // If in builder mode, or in viewer mode when offer hasn't been accepted
      (viewer && imported && offering)); // If in viewer mode when offer has not been accepted and showing the offering side
  const disableReadOnly = offering && viewer && imported;
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L104-104)
```typescript
  const showInvalid = !isValidating && isValid === false;
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L193-194)
```typescript
  const canAccept = !!offerData;
  const disableAccept = missingOfferedCATs || showInvalid || isExpired;
```

**File:** packages/gui/src/hooks/useAcceptOfferHook.tsx (L87-91)
```typescript
    const confirmedAccept = await openDialog(<OfferAcceptConfirmationDialog offeredUnknownCATs={offeredUnknownCATs} />);

    if (!confirmedAccept) {
      return;
    }
```

**File:** packages/gui/src/hooks/useAcceptOfferHook.tsx (L95-114)
```typescript
      const response = await takeOffer({ offer: offerData, fee: feeInMojos }).unwrap();

      await openDialog(
        <AlertDialog title={<Trans>Success</Trans>}>
          {response.message ?? <Trans>Offer has been accepted and is awaiting confirmation.</Trans>}
        </AlertDialog>,
      );

      onSuccess?.();
    } catch (e) {
      let error = e as Error;

      if (error.message.startsWith('insufficient funds')) {
        error = new Error(t`
          Insufficient funds available to accept offer. Ensure that your
          spendable balance is sufficient to cover the offer amount.
        `);
      }
      showError(error);
    } finally {
```
