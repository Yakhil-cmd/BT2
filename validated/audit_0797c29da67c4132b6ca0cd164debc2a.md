### Title
Attacker-Controlled `puzzleHash` in Blockchain Notification Pre-populates Counter-Offer Notification Destination with Attacker Address — (`packages/gui/src/components/offers2/OfferIncomingTable.tsx`, `packages/gui/src/components/offers/OfferManager.tsx`)

---

### Summary

An unprivileged on-chain attacker can broadcast a blockchain notification with a `ph` field containing an attacker-controlled puzzle hash. The GUI extracts this value without any validation and uses it — without user visibility or ability to change it — as the pre-populated, locked destination address for the counter-offer notification. The user's counter-offer notification (including a small XCH fee) is sent to the attacker instead of the original offer sender, and the attacker receives the counter-offer file and can accept it.

---

### Finding Description

**Entrypoint — `prepareNotifications` in `useBlockchainNotifications.tsx`:**

The `ph` field from the raw blockchain notification message is extracted and stored directly as `puzzleHash` on the notification object with no format validation, ownership check, or binding to the actual on-chain sender address: [1](#0-0) 

**Path 1 — via "Counter" button (`OfferIncomingTable.handleCounterOffer`):**

`puzzleHash` is converted to bech32m and passed as `address` to the builder route: [2](#0-1) 

However, this path has a double-conversion defect: `handleOfferCreated` in `OfferManager.tsx` calls `toBech32m` again on the already-bech32m-encoded string, which likely produces garbage or throws, breaking this specific path.

**Path 2 — via "View" button → `OfferBuilderViewer.handleCounterOffer` (working exploit path):**

`handleShowOffer` passes the raw `puzzleHash` hex directly as `address` to the offer view route: [3](#0-2) 

`OfferBuilderViewer.handleCounterOffer` then forwards this raw `puzzleHash` as `address` to the builder: [4](#0-3) 

**`handleOfferCreated` in `OfferManager.tsx` correctly converts the raw puzzle hash to bech32m and passes it to `OfferShareDialog`:** [5](#0-4) 

**`NotificationSendDialog` uses this address as a locked, non-editable destination:**

The address field is rendered `disabled` — the user cannot change it: [6](#0-5) 

The notification is sent to `fromBech32m(address)` — the attacker's puzzle hash — with no validation that this address corresponds to the original offer sender.

---

### Impact Explanation

- The user's counter-offer notification (carrying a small XCH fee and the counter-offer URL) is sent to the attacker's wallet, not the original offer sender.
- The attacker receives the counter-offer file and can accept it on-chain.
- The original offer sender never receives the counter-offer.
- The user cannot change the destination address — it is pre-populated and locked in the UI.
- The user's offered assets in the counter-offer are only transferred if the attacker provides the requested assets, so direct theft without consideration is not possible. However, the attacker gains exclusive access to the counter-offer and can accept it on favorable terms, while the legitimate counterparty is excluded.

---

### Likelihood Explanation

Any node on the Chia network can broadcast a notification to any puzzle hash. The attacker only needs to know the victim's receive address (publicly derivable from any prior transaction). The `ph` field is completely attacker-controlled and requires no special privilege. The victim only needs to click "View" and then "Counter Offer" — a normal user workflow.

---

### Recommendation

1. **Validate `puzzleHash` format** in `prepareNotifications` — reject values that are not valid 32-byte hex strings.
2. **Do not trust the `ph` field as the counter-offer destination.** The counter-offer notification destination should be derived from the on-chain sender of the notification coin (the coin's puzzle hash that funded the notification), not from the message payload.
3. **Allow the user to edit the notification destination address** in `NotificationSendDialog` rather than locking it as `disabled`.
4. **Display the resolved bech32m address** prominently before the user confirms sending, with a clear warning that this is where the counter-offer will be sent.

---

### Proof of Concept

1. Attacker controls wallet with puzzle hash `ATTACKER_PH`.
2. Attacker broadcasts a blockchain notification to the victim's puzzle hash with payload:
   ```json
   {"v":1,"t":1,"d":{"u":"https://attacker.com/fake_offer.offer","ph":"ATTACKER_PH"}}
   ```
3. Victim's GUI receives the notification via `useGetNotificationsQuery`. `prepareNotifications` extracts `puzzleHash = ATTACKER_PH` with no validation.
4. Victim clicks "View" on the notification → `handleShowOffer` passes `address: ATTACKER_PH` (raw hex) to `/dashboard/offers/view`.
5. Victim clicks "Counter Offer" → `OfferBuilderViewer.handleCounterOffer` passes `address: ATTACKER_PH` to `/dashboard/offers/builder`.
6. Victim fills in counter-offer terms and clicks "Create Counter Offer".
7. `handleOfferCreated` converts `ATTACKER_PH` to `xch1<attacker_address>` and opens `OfferShareDialog` with this address locked in.
8. Victim clicks "Send Message" → notification with counter-offer URL is sent to attacker's wallet.
9. Attacker receives the counter-offer and can accept it on-chain, excluding the original offer sender entirely.

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

**File:** packages/gui/src/components/offers2/OfferIncomingTable.tsx (L175-206)
```typescript
  async function handleCounterOffer(notification: Notification) {
    try {
      const puzzleHash = 'puzzleHash' in notification ? notification.puzzleHash : undefined;
      const offerId =
        'offerURL' in notification
          ? notification.offerURL
          : 'offerData' in notification
            ? notification.offerData
            : undefined;
      const offerState = getOffer(offerId);

      if (!offerState || !puzzleHash || !currencyCode) {
        return;
      }

      const address = currencyCode && puzzleHash ? toBech32m(puzzleHash, currencyCode.toLowerCase()) : '';
      const offerSummary = offerState.offer?.summary;

      if (!offerSummary || isDataLayerOfferSummary(offerSummary)) {
        return;
      }

      const offer = offerToOfferBuilderData(offerSummary);

      navigate('/dashboard/offers/builder', {
        state: {
          referrerPath: location.pathname,
          isCounterOffer: true,
          address,
          offer,
        },
      });
```

**File:** packages/gui/src/components/offers2/OfferIncomingTable.tsx (L220-248)
```typescript
  function handleShowOffer(notification: Notification) {
    const puzzleHash = 'puzzleHash' in notification ? notification.puzzleHash : undefined;
    const offerId =
      'offerURL' in notification
        ? notification.offerURL
        : 'offerData' in notification
          ? notification.offerData
          : undefined;
    const offerState = getOffer(offerId);

    if (!offerState) {
      return;
    }

    const offerData = offerState.offer?.data;
    const offerSummary = offerState.offer?.summary;
    const canCounterOffer = !isDataLayerOfferSummary(offerSummary) && puzzleHash && puzzleHash.length > 0;

    navigate('/dashboard/offers/view', {
      state: {
        referrerPath: location.pathname,
        offerData,
        offerSummary,
        imported: true,
        canCounterOffer,
        address: puzzleHash,
      },
    });
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
