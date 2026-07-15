### Title
Missing Credential Guard on CR-CAT Offer Acceptance Allows Asset Loss — (`packages/gui/src/components/offers2/OfferBuilderViewer.tsx`)

---

### Summary

The offer viewer's `disableAccept` gate does not check whether the accepting user holds valid Verifiable Credentials (VCs) for CR-CAT tokens they would receive. An unprivileged attacker can publish an offer that trades CR-CAT tokens (requiring specific VC flags) for XCH or other assets. A victim who lacks the required credentials can still click "Accept Offer," pay their side of the trade, and receive CR-CAT tokens permanently stuck in `pendingApprovalBalance` — unclaimable without credentials they do not hold.

---

### Finding Description

CR-CAT (Credential-Restricted CAT) tokens require the holder to possess a Verifiable Credential (VC) with specific proof flags from an authorized provider before the tokens can be claimed via `crcat_approve_pending`. When a CR-CAT offer is viewed, `OfferBuilderToken` renders `CrCatFlags` which shows red error icons if the viewer lacks the required credentials — but this is purely informational.

The acceptance gate in `OfferBuilderViewer` is:

```ts
const missingOfferedCATs = !!offeredUnknownCATs?.length;
const disableAccept = missingOfferedCATs || showInvalid || isExpired;
```

`missingOfferedCATs` only checks whether the taker's *outgoing* CAT wallets exist locally. There is no corresponding check for whether the taker has valid VC credentials for the CR-CAT tokens they would *receive*. The "Accept Offer" button is therefore enabled even when `CrCatFlags` is displaying red error icons for every required credential flag. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

A victim who accepts such an offer:

1. Pays their side (XCH, CATs, NFTs) — this is irreversible once the offer is taken.
2. Receives CR-CAT tokens that land in `pendingApprovalBalance`.
3. Cannot call `crcat_approve_pending` successfully without the required VC from the authorized provider.

If the victim cannot obtain the required credential (e.g., the authorized provider is permissioned, KYC-gated, or the attacker controls a fake provider ID), the received CR-CAT tokens are permanently unspendable. The victim has made an irreversible payment for assets they cannot use. [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

The attacker only needs to publish a publicly accessible offer file containing CR-CAT tokens with restrictive credential requirements. No special privileges are required. The victim must have the CR-CAT asset ID in their local wallet (so `missingOfferedCATs` is false) but lack the VC — a realistic scenario for any CR-CAT token where credential issuance is controlled. The GUI's only protection is the informational `CrCatFlags` chip display, which a user may not understand or notice before clicking "Accept Offer." [6](#0-5) 

---

### Recommendation

Extend `disableAccept` to also block acceptance when the taker lacks valid credentials for any CR-CAT token in the offered (received) side of the trade. The `CrCatFlags` component already computes `haveValidCredentialsForFlags`; this boolean should be surfaced upward and incorporated into the `disableAccept` condition in `OfferBuilderViewer`, or at minimum trigger a blocking confirmation dialog analogous to the `OfferAcceptConfirmationDialog` used for unknown CATs. [7](#0-6) 

---

### Proof of Concept

1. Attacker creates an offer: offer 100 units of a CR-CAT (requiring flag `kyc_verified` from a permissioned provider) in exchange for 1 XCH.
2. Attacker distributes the offer file/string.
3. Victim imports the offer. `OfferBuilderToken` renders the CR-CAT with `CrCatFlags` showing a red `ErrorIcon` for `kyc_verified` — but `disableAccept` evaluates to `false` because the victim's wallet knows the CAT asset ID.
4. Victim clicks "Accept Offer." `handleAcceptOffer` → `offerBuilderRef.current?.submit()` → `handleSubmit` → `acceptOffer(...)` executes with no credential guard.
5. Victim's 1 XCH is spent. Victim receives 100 CR-CAT in `pendingApprovalBalance`.
6. Victim opens `CrCatApprovePendingDialog`, submits fee — `crcat_approve_pending` fails or the tokens remain unclaimable because the victim has no valid VC from the authorized provider.
7. Victim has lost 1 XCH for tokens they cannot spend. [8](#0-7) [9](#0-8)

### Citations

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L190-194)
```typescript
  const missingOfferedCATs = !!offeredUnknownCATs?.length;
  const missingRequestedCATs = !!requestedUnknownCATs?.length;

  const canAccept = !!offerData;
  const disableAccept = missingOfferedCATs || showInvalid || isExpired;
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L232-242)
```typescript
  async function handleAcceptOffer() {
    if (!isWalletSynced) {
      await openDialog(
        <AlertDialog>
          <Trans>Please wait for wallet synchronization</Trans>
        </AlertDialog>,
      );
    } else {
      offerBuilderRef.current?.submit();
    }
  }
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L363-375)
```typescript
              {canAccept && (
                <ButtonLoading
                  variant="contained"
                  color="primary"
                  onClick={handleAcceptOffer}
                  isLoading={isAccepting}
                  disableElevation
                  disabled={disableAccept}
                >
                  <Trans>Accept Offer</Trans>
                </ButtonLoading>
              )}
            </Flex>
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

**File:** packages/wallets/src/components/card/WalletCardCRCatApprove.tsx (L35-36)
```typescript
  const value = walletBalance?.pendingApprovalBalance || 0;

```

**File:** packages/wallets/src/components/crCat/CrCatApprovePendingDialog.tsx (L68-75)
```typescript
  async function handleSubmit(values: FormData) {
    const { fee } = values;
    const feeInMojos = chiaToMojo(fee);
    const response = await crCatApprovePending({ walletId, minAmountToClaim: amount, fee: feeInMojos }).unwrap();

    if (!response.transactions || response.transactions.length === 0) {
      throw new Error('No transaction returned');
    }
```

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

**File:** packages/gui/src/components/offers/OfferAcceptConfirmationDialog.tsx (L16-63)
```typescript
export default function OfferAcceptConfirmationDialog(props: OfferAcceptConfirmationDialogProps): React.ReactElement {
  const { offeredUnknownCATs = [], ...rest } = props;

  return (
    <ConfirmDialog
      title={<Trans>Accept Offer</Trans>}
      confirmTitle={<Trans>Yes, Accept Offer</Trans>}
      confirmColor="primary"
      cancelTitle={<Trans>Cancel</Trans>}
      {...rest}
    >
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
