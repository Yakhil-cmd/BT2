Now I have a complete picture of the full code path. Let me trace it precisely.

### Title
Attacker-Controlled `ph` Field in Blockchain Notification Blindly Trusted as Counter-Offer Destination — (`packages/gui/src/components/notification/NotificationOffer.tsx`, `packages/gui/src/hooks/useBlockchainNotifications.tsx`)

---

### Summary

An unprivileged attacker can send an on-chain notification with `ph` set to their own puzzle hash. The GUI blindly trusts this value as the counter-offer reply address, pre-fills it into a **disabled** (non-editable) address field in `NotificationSendDialog`, and sends the victim's counter-offer notification to the attacker. The attacker can then accept the counter-offer, causing the victim's assets to be transferred under false pretenses.

---

### Finding Description

**Step 1 — Attacker-controlled entry point: `prepareNotifications`**

In `useBlockchainNotifications.tsx`, the `ph` field from the raw on-chain notification payload is extracted with no validation that it belongs to the actual notification sender: [1](#0-0) 

The `puzzleHash` is stored directly into the `Notification` object. Any on-chain actor can set `ph` to any arbitrary hex string.

**Step 2 — `NotificationOffer.handleClick` passes it as `address`**

When the victim clicks the notification, `handleClick` navigates to `/dashboard/offers/view` with the attacker-controlled `puzzleHash` as the `address` field in router state: [2](#0-1) 

**Step 3 — `OfferBuilderViewer.handleCounterOffer` propagates it**

When the victim clicks "Counter Offer", the `address` is forwarded to `/dashboard/offers/builder`: [3](#0-2) 

**Step 4 — `CreateOfferBuilder` passes `address` to `onOfferCreated`**

After the victim creates the counter-offer, `address` is passed through to the callback: [4](#0-3) 

**Step 5 — `CreateOffer.handleOfferCreated` converts and passes to `OfferShareDialog`**

The puzzle hash is converted to bech32m and passed as `address` to `OfferShareDialog`: [5](#0-4) 

**Step 6 — `OfferShareDialog` uses it as `notificationDestination`**

Each share service dialog (Dexie, Spacescan, Offerpool) sets `notificationDestination = address || nftId` and passes it to `NotificationSendDialog`: [6](#0-5) 

**Step 7 — `NotificationSendDialog` pre-fills the address and disables the field**

The attacker's address is set as the default value, and the address `TextField` is rendered with `disabled`, preventing the user from correcting it: [7](#0-6) [8](#0-7) 

**Step 8 — Counter-offer notification is sent to the attacker**

`handleSubmit` derives `targetPuzzleHash` from the pre-filled (attacker-controlled) address and calls `sendNotification`: [9](#0-8) 

---

### Impact Explanation

The victim's counter-offer notification is delivered to the attacker's wallet, not the original offer sender's. The attacker receives the counter-offer file URL and can accept the counter-offer, causing the victim's offered assets (XCH, CAT, NFT) to be transferred to the attacker. The victim has no opportunity to detect or correct the misdirection because the address field is `disabled`.

This fits the **High** impact category: *"unsafe trust of notification state that causes a user to send [assets] to the wrong destination."*

---

### Likelihood Explanation

- Requires only the ability to send an on-chain notification (permissionless on Chia mainnet, costs ~0.0001 XCH)
- No special privileges, no key compromise, no phishing beyond the notification itself
- The victim only needs to click "Counter" on a notification they received — a normal, expected workflow
- The disabled address field gives the victim no recourse

---

### Recommendation

1. **Do not trust `ph` as the counter-offer destination without verification.** At minimum, verify that the notification was sent *from* the coin whose puzzle hash matches `ph` (i.e., the on-chain sender address must match the claimed `ph`).
2. **Make the address field editable** in `NotificationSendDialog` so users can inspect and correct the destination before sending.
3. **Display a clear warning** when the counter-offer destination address differs from the on-chain sender of the notification.
4. **Validate `ph` format** (length, hex encoding) before storing it in the `Notification` object in `prepareNotifications`.

---

### Proof of Concept

1. Attacker crafts a notification payload: `{"v":1,"t":1,"d":{"u":"https://dexie.space/offers/legitimate-offer","ph":"<attacker_puzzle_hash_hex>"}}`
2. Attacker sends this notification on-chain to victim's puzzle hash (costs ~0.0001 XCH).
3. Victim opens the GUI, sees "You have a new offer", clicks the notification.
4. Victim is shown the offer and clicks "Counter Offer".
5. Victim fills in counter-offer terms and clicks "Create Counter Offer".
6. The share dialog opens; victim clicks "Share on Dexie" → "Send Notification".
7. `NotificationSendDialog` shows the attacker's address pre-filled and **disabled**.
8. Victim clicks send — the counter-offer notification is delivered to the attacker.
9. Attacker accepts the counter-offer; victim's assets are transferred.

**Assertion for integration test:** set `ph` in the notification to an address that does not match the on-chain sender; assert that the GUI either rejects the counter-offer flow or displays a mismatch warning before allowing the notification to be sent.

### Citations

**File:** packages/gui/src/hooks/useBlockchainNotifications.tsx (L98-110)
```typescript
              if (type === 1) {
                const { u: url, ph: puzzleHash } = data;

                if (puzzleHash) {
                  return {
                    // type: NotificationType.COUNTER_OFFER,
                    type: NotificationType.OFFER,
                    id,
                    source: 'BLOCKCHAIN',
                    timestamp: timestampData.timestamp,
                    offerURL: url,
                    puzzleHash,
                  };
```

**File:** packages/gui/src/components/notification/NotificationOffer.tsx (L56-71)
```typescript
  function handleClick() {
    onClick?.();

    if (offer && offer.summary) {
      navigate('/dashboard/offers/view', {
        state: {
          referrerPath: location.pathname,
          offerData: offer.data,
          offerSummary: offer.summary,
          imported: true,
          canCounterOffer,
          address: 'puzzleHash' in notification ? notification.puzzleHash : undefined,
        },
      });
    }
  }
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L219-230)
```typescript
  function handleCounterOffer() {
    const offer = offerToOfferBuilderData(offerSummary as OfferSummary, false, '');
    navigate('/dashboard/offers/builder', {
      state: {
        referrerPath: location.pathname,
        isCounterOffer: true,
        address,
        offer,
      },
      replace: true,
    });
  }
```

**File:** packages/gui/src/components/offers2/CreateOfferBuilder.tsx (L140-142)
```typescript
        if (!suppressShareOnCreate) {
          onOfferCreated({ offerRecord, offerData, address, nftId });
        }
```

**File:** packages/gui/src/components/offers/OfferManager.tsx (L445-458)
```typescript
  async function handleOfferCreated(obj: { offerRecord: any; offerData: any; address?: string }) {
    const { offerRecord, offerData, address: ph } = obj;
    const address = ph && currencyCode ? toBech32m(ph, currencyCode.toLowerCase()) : undefined;

    await openDialog(
      <OfferShareDialog
        offerRecord={offerRecord}
        offerData={offerData as string}
        showSuppressionCheckbox
        exportOffer={() => saveOffer(offerRecord.tradeId)}
        testnet={testnet}
        address={address}
      />,
    );
```

**File:** packages/gui/src/components/offers/OfferShareDialog.tsx (L431-432)
```typescript
  const notificationDestination = address || nftId;
  const notificationDestinationType = address ? 'address' : 'nft';
```

**File:** packages/gui/src/components/notification/NotificationSendDialog.tsx (L72-76)
```typescript
  const defaultAddress = isNFTOffer ? '' : destination;
  const launcherId = launcherIdFromNFTId(isNFTOffer ? destination : '');
  const methods = useForm<NotificationSendDialogFormData>({
    defaultValues: { address: defaultAddress, amount: '0.0001', allowCounterOffer: true, fee: '' },
  });
```

**File:** packages/gui/src/components/notification/NotificationSendDialog.tsx (L117-135)
```typescript
  async function handleSubmit(values: NotificationSendDialogFormData) {
    const { amount, fee } = values;
    const targetPuzzleHash = fromBech32m(address);
    const senderPuzzleHash = allowCounterOffer ? fromBech32m(currentAddress) : undefined;
    const amountMojos = chiaToMojo(amount);
    const feeMojos = chiaToMojo(fee);
    const payload = createOfferNotificationPayload({ offerURL, puzzleHash: senderPuzzleHash });
    let success = false;
    let error = '';

    const hexMessage = arrToHex(new TextEncoder().encode(payload));

    try {
      await sendNotification({
        target: targetPuzzleHash,
        amount: amountMojos,
        message: hexMessage,
        fee: feeMojos,
      }).unwrap();
```

**File:** packages/gui/src/components/notification/NotificationSendDialog.tsx (L218-232)
```typescript
                        <TextField
                          variant="filled"
                          name="address"
                          label={<Trans>Address</Trans>}
                          InputProps={{
                            endAdornment: (
                              <InputAdornment position="end">
                                <CopyToClipboard value={address} />
                              </InputAdornment>
                            ),
                          }}
                          disabled
                          fullWidth
                          // required
                        />
```
