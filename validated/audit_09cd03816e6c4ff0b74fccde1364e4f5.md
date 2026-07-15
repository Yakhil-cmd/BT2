### Title
No Blocking Guard When Accepting Offers Containing CR-CATs the Taker Cannot Spend - (File: packages/gui/src/components/offers2/OfferBuilderViewer.tsx)

### Summary
The offer acceptance flow in the Chia GUI does not block or explicitly warn users in the confirmation dialog when they are about to accept an offer where the received CR-CATs (Credential-Restricted CATs) require Verifiable Credentials (VCs) they do not possess. The "Accept Offer" button remains enabled and the confirmation dialog is silent about credential restrictions, allowing a user to permanently pay real assets (XCH/CATs) while receiving CR-CATs they cannot spend.

### Finding Description
CR-CATs are CATs whose spend is gated behind specific Verifiable Credentials issued by authorized providers. When a user views an imported offer containing CR-CATs, `offerToOfferBuilderData` calls `extractCrCatData` to parse the `credential restricted` puzzle layer from the offer summary's `infos` field and attaches it to each token entry as `crCat`. [1](#0-0) 

This `crCat` object is then read by `OfferBuilderToken` via `useWatch`, and `CrCatFlags` renders a chip with an error icon when the viewing wallet lacks the required credential. [2](#0-1) 

`CrCatFlags` computes `haveValidCredentialsForFlags` by cross-referencing the user's VC list against the required flags and authorized providers. When the user lacks credentials, an error icon is shown in a tooltip — but this is only a passive visual indicator. [3](#0-2) 

The critical missing guard is in `OfferBuilderViewer`. The `disableAccept` flag only checks for `missingOfferedCATs` (unknown CATs the taker must pay), `showInvalid`, and `isExpired`. There is no check for whether the taker has the required credentials for CR-CATs they would **receive**. [4](#0-3) 

In `useAcceptOfferHook`, `offeredUnknownCATs` only identifies CATs not present in the user's wallet list — it does not detect CR-CATs with unmet credential requirements. The `OfferAcceptConfirmationDialog` that follows only warns about unknown CATs, never about credential restrictions. [5](#0-4) [6](#0-5) 

### Impact Explanation
A user who accepts such an offer pays real XCH or CATs and receives CR-CATs they cannot spend without credentials they do not hold. If the required credentials are from an authorized provider the user cannot access, the received CR-CATs are permanently unspendable. This is a direct, irreversible asset loss: the user's payment is consumed on-chain and the received tokens are locked.

### Likelihood Explanation
Any unprivileged user can create an offer offering CR-CATs with restrictive credential requirements. CR-CATs are a supported, documented Chia protocol feature. A victim browsing an offer file or link may not understand the significance of the small error-icon chip rendered by `CrCatFlags` inside the offer builder token row, especially since the prominent confirmation dialog says nothing about credential restrictions. The accept button being fully enabled reinforces the false impression that the offer is safe to accept.

### Recommendation
1. In `OfferBuilderViewer`, extend `disableAccept` to also be `true` when any received token has a `crCat` restriction and `CrCatFlags` reports that the user lacks the required credentials.
2. In `useAcceptOfferHook` / `OfferAcceptConfirmationDialog`, add an explicit blocking warning listing any received CR-CATs for which the user does not hold valid credentials, analogous to the existing `offeredUnknownCATs` warning.

### Proof of Concept
1. Attacker holds CR-CATs requiring credential flag `kyc_verified` from authorized provider `0xABCD…`.
2. Attacker creates and shares an offer: "100 CR-CAT for 1 XCH."
3. Victim opens the offer in the GUI. `OfferBuilderToken` renders the `CrCatFlags` chip with an error icon (victim lacks `kyc_verified`), but the "Accept Offer" button is fully enabled.
4. Victim clicks "Accept Offer." `handleAcceptOffer` calls `offerBuilderRef.current?.submit()`, which calls `acceptOffer` in `useAcceptOfferHook`.
5. `offeredUnknownCATs` is empty (the CR-CAT asset ID is known to the wallet), so no blocking warning fires.
6. `OfferAcceptConfirmationDialog` appears with no mention of credential restrictions. Victim clicks "Yes, Accept Offer."
7. `takeOffer` is dispatched; 1 XCH leaves the victim's wallet. Victim receives 100 CR-CAT they cannot spend without `kyc_verified` from provider `0xABCD…`.
8. Victim has permanently lost 1 XCH and holds unspendable tokens. [7](#0-6)

### Citations

**File:** packages/gui/src/util/offerToOfferBuilderData.ts (L93-101)
```typescript
function extractCrCatData(info: OfferSummaryCATInfo) {
  if (!info.also) return undefined;
  if (info.also.type !== 'credential restricted') return undefined;
  const { flags, authorizedProviders } = info.also;
  return {
    flags,
    authorizedProviders,
  };
}
```

**File:** packages/gui/src/components/offers2/OfferBuilderToken.tsx (L56-67)
```typescript
          {crCat && (
            <Flex gap={1} flexDirection="column" sx={{ mt: 2 }}>
              <Typography variant="body1">
                <Trans>CAT credential restrictions</Trans>:
              </Typography>
              <CrCatFlags restrictions={crCat} />
              <Typography variant="body1">
                <Trans>Authorized providers</Trans>:
              </Typography>
              <CrCatAuthorizedProviders authorizedProviders={crCat.authorizedProviders} />
            </Flex>
          )}
```

**File:** packages/wallets/src/components/crCat/CrCatFlags.tsx (L23-57)
```typescript
  const haveValidCredentialsForFlags = useMemo(() => {
    if (isGetVCListLoading || !restrictions?.flags || restrictions.flags.length === 0 || !vcs || !vcs.proofs) {
      return null;
    }

    // since the flags are the keys, the API abstraction camelCases them
    const flags = restrictions.flags.map((flag) => ({ flag, flagCamelCase: camelCase(flag) }));

    const toReturn: string[] = [];

    Object.entries(vcs.proofs).forEach(([proofHash, proofObject]) => {
      if (proofObject)
        Object.keys(proofObject).forEach((proofFlag) => {
          // check if we have the proof flag
          const foundFlag = flags.find((flag) => flag.flagCamelCase === proofFlag);
          if (foundFlag) {
            // check if we have a VC with the proofHash
            vcs.vcRecords.forEach((vcRecord) => {
              if (vcRecord.vc.proofHash === `0x${proofHash}`) {
                // check if the VC is from the authorized provider
                if (
                  restrictions.authorizedProviders
                    .map((provider) => (provider.startsWith('0x') ? provider : `0x${provider}`))
                    .includes(vcRecord.vc.proofProvider)
                ) {
                  toReturn.push(foundFlag.flag);
                }
              }
            });
          }
        });
    });

    return toReturn;
  }, [isGetVCListLoading, restrictions, vcs]);
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L190-194)
```typescript
  const missingOfferedCATs = !!offeredUnknownCATs?.length;
  const missingRequestedCATs = !!requestedUnknownCATs?.length;

  const canAccept = !!offerData;
  const disableAccept = missingOfferedCATs || showInvalid || isExpired;
```

**File:** packages/gui/src/hooks/useAcceptOfferHook.tsx (L43-95)
```typescript
    const offerBuilderData = offerToOfferBuilderData(offerSummary, true);
    const { assetsToUnlock } = await offerBuilderDataToOffer({
      data: offerBuilderData,
      wallets,
      offers: offers || [],
      validateOnly: false,
      considerNftRoyalty: true,
      allowEmptyOfferColumn: true, // When accepting a one-sided offer, nothing is required in the offer column
      allowUnknownRequestedCATs: true, // When accepting an offer containing unknown CATs, we can still accept it
    });

    const assetsRequiredToBeUnlocked = [];
    const assetsBetterToBeUnlocked = [];
    for (let i = 0; i < assetsToUnlock.length; i++) {
      const atu = assetsToUnlock[i];
      if (atu.status === 'conflictsWithNewOffer') {
        assetsRequiredToBeUnlocked.push(atu);
      } else if (atu.status === 'alsoUsedInNewOfferWithoutConflict') {
        assetsBetterToBeUnlocked.push(atu);
      }
    }

    if (assetsRequiredToBeUnlocked.length + assetsBetterToBeUnlocked.length > 0) {
      const dialog = (
        <OfferEditorConflictAlertDialog
          assetsToUnlock={assetsRequiredToBeUnlocked}
          // assetsBetterUnlocked={assetsBetterToBeUnlocked}
          assetsBetterUnlocked={[]} // Ignoring assetsBetterToBeUnlocked to avoid displaying the dialog unnecessarily
        />
      );
      const confirmedToProceed = await openDialog(dialog);
      if (!confirmedToProceed) {
        return;
      }
    }

    const feeInMojos: BigNumber = fee ? chiaToMojo(fee) : new BigNumber(0);
    const offeredUnknownCATs: string[] = Object.entries(offerSummary.offered)
      .filter(
        ([assetId]) =>
          offerAssetTypeForAssetId(assetId, offerSummary) !== OfferAsset.NFT && lookupByAssetId(assetId) === undefined,
      )
      .map(([assetId]) => assetId);

    const confirmedAccept = await openDialog(<OfferAcceptConfirmationDialog offeredUnknownCATs={offeredUnknownCATs} />);

    if (!confirmedAccept) {
      return;
    }
    try {
      onUpdate?.(true);

      const response = await takeOffer({ offer: offerData, fee: feeInMojos }).unwrap();
```

**File:** packages/gui/src/components/offers/OfferAcceptConfirmationDialog.tsx (L27-63)
```typescript
      <Flex flexDirection="column" gap={3}>
        {offeredUnknownCATs.length > 0 && (
          <>
            <Flex flexDirection="column" gap={1}>
              <Typography variant="h6">
                <Trans>Warning</Trans>
              </Typography>
              <Typography variant="body1">
                <Trans>
                  One or more unknown tokens are being offered. Please verify that the asset IDs of the tokens listed
                  below match the asset IDs of the tokens you expect to receive.
                </Trans>
              </Typography>
              <Typography variant="subtitle1">Unknown CATs:</Typography>
              <StyledSummaryBox>
                <Flex flexDirection="column">
                  {offeredUnknownCATs.map((assetId) => (
                    <Flex alignItems="center" justifyContent="space-between" gap={1}>
                      <Typography variant="caption">{assetId.toLowerCase()}</Typography>
                      <CopyToClipboard value={assetId.toLowerCase()} fontSize="small" />
                    </Flex>
                  ))}
                </Flex>
              </StyledSummaryBox>
            </Flex>
            <Divider />
          </>
        )}
        <Typography>
          <Trans>
            Once you accept this offer, you will not be able to cancel the transaction. Are you sure you want to accept
            this offer?
          </Trans>
        </Typography>
      </Flex>
    </ConfirmDialog>
  );
```
