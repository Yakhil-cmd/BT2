The full call chain is now confirmed. Here is the complete trace:

---

### Title
Unvalidated `ph` Field in Blockchain Notification Payload Causes Counter-Offer Notification to Be Sent to Attacker-Controlled Address — (`packages/gui/src/hooks/useBlockchainNotifications.tsx`)

---

### Summary

An unprivileged attacker who can send a Chia blockchain notification (costing only a small on-chain fee) can set the `ph` field to their own bech32m address. The GUI trusts this value without any validation, propagates it as `puzzleHash` through the notification object, and ultimately pre-populates the counter-offer notification send dialog with the attacker's address. The victim is caused to send their counter-offer notification to the attacker instead of the legitimate offer sender.

---

### Finding Description

**Step 1 — Unvalidated ingestion of `data.ph`**

In `useBlockchainNotifications.tsx`, the `ph` field is extracted from the decoded JSON payload and stored directly as `puzzleHash` with no bech32 decoding, hex validation, or length check:

```
const { u: url, ph: puzzleHash } = data;
``` [1](#0-0) 

The raw attacker-controlled string is stored in the notification object and passed downstream.

**Step 2 — `toBech32m` prefix-bypass**

`toBech32m` has a short-circuit: if the input already starts with the expected prefix (e.g. `xch`), it is returned unchanged without any re-encoding or validation:

```ts
export default function toBech32m(value: string, prefix: string): string {
  if (value.startsWith(prefix)) {
    return value;   // ← attacker's bech32m address returned as-is
  }
  ...
}
``` [2](#0-1) 

An attacker who sets `ph = xch1<their_address>` passes through every `toBech32m` call unchanged.

**Step 3 — Two code paths propagate the address**

*Path A — `OfferIncomingTable.handleCounterOffer`*: calls `toBech32m(puzzleHash, currencyCode.toLowerCase())`, which returns the attacker's address as-is, then navigates to `/dashboard/offers/builder` with `address = attacker_address`. [3](#0-2) 

*Path B — `NotificationOffer.handleClick`*: passes `notification.puzzleHash` (the raw attacker string) directly as `address` in the navigation state to `/dashboard/offers/view`, which then forwards it to `OfferBuilderViewer.handleCounterOffer` → `/dashboard/offers/builder`. [4](#0-3) 

**Step 4 — `CreateOfferBuilder` passes `address` to `onOfferCreated`**

After the victim creates the counter-offer, `handleSubmit` calls:

```ts
onOfferCreated({ offerRecord, offerData, address, nftId });
``` [5](#0-4) 

**Step 5 — `handleOfferCreated` in `OfferManager` applies `toBech32m` again (bypass again) and opens `OfferShareDialog`**

```ts
async function handleOfferCreated(obj: { offerRecord: any; offerData: any; address?: string }) {
  const { offerRecord, offerData, address: ph } = obj;
  const address = ph && currencyCode ? toBech32m(ph, currencyCode.toLowerCase()) : undefined;
  await openDialog(
    <OfferShareDialog ... address={address} />,
  );
}
``` [6](#0-5) 

`toBech32m` again returns the attacker's address unchanged. `OfferShareDialog` receives `address = xch1<attacker>` and pre-populates the `NotificationSendDialog` destination field with it.

---

### Impact Explanation

The victim is caused to send their counter-offer notification to the attacker's address instead of the legitimate offer sender. The attacker receives the counter-offer and can accept it. This is a concrete spoofing/misdirection of notification destination state, fitting the defined High impact: *"Corruption, spoofing, or unsafe trust of… notification… state that causes a user to… send… [to] the wrong… destination."*

**Important nuance vs. the question's claim**: In Chia's trustless offer system, the counter-offer file itself does not "send XCH to the attacker's address" — it is a cryptographic construct anyone can accept. The actual harm is that the notification (containing the counter-offer) is delivered to the attacker instead of the intended party, allowing the attacker to accept the counter-offer on the victim's stated terms. The victim's assets are not unconditionally transferred; the attacker must provide the requested assets to accept. However, the attacker controls the original offer terms and can craft them to make the counter-offer favorable, and the victim loses the ability to negotiate with the intended counterparty.

---

### Likelihood Explanation

- Sending a blockchain notification requires only a small on-chain fee and no special privileges.
- The `ph` field is completely free-form; no schema enforcement exists anywhere in the GUI.
- The `toBech32m` bypass is triggered simply by supplying a valid bech32m address (starting with `xch`/`txch`).
- The victim only needs to click "Counter Offer" and then "Send Message" in the pre-populated dialog — both are normal user actions.

---

### Recommendation

1. **Validate `data.ph` in `useBlockchainNotifications`**: accept only 64-character lowercase hex strings (a raw puzzle hash). Reject or ignore any value that does not match `/^[0-9a-f]{64}$/`.
2. **Fix `toBech32m`**: the prefix short-circuit should decode and re-encode the value to verify it is a valid bech32m encoding of a 32-byte puzzle hash, not simply pass arbitrary strings through.
3. **Display the resolved address to the user** in the counter-offer flow before sending the notification, with a clear warning that this address came from the incoming notification.

---

### Proof of Concept

1. Craft a blockchain notification message (hex-encoded JSON):
   ```json
   {"v":1,"t":1,"d":{"u":"<valid_offer_url>","ph":"xch1<attacker_bech32m_address>"}}
   ```
2. Send it on-chain to the victim's puzzle hash (standard `send_notification` RPC).
3. Victim's GUI receives and displays the notification.
4. Victim clicks the notification → views the offer → clicks **Counter Offer** → fills in counter-offer terms → clicks **Create Counter Offer**.
5. `handleOfferCreated` fires; `OfferShareDialog` opens with the attacker's address pre-populated in the notification destination field.
6. Victim clicks **Send Notification** → counter-offer notification is delivered to the attacker's address.
7. Attacker accepts the counter-offer on the victim's stated terms.

**Assert**: `toBech32m("xch1<attacker>", "xch")` returns `"xch1<attacker>"` unchanged (line 12–13 of `toBech32m.ts`), confirming the bypass is unconditional for any valid bech32m address.

### Citations

**File:** packages/gui/src/hooks/useBlockchainNotifications.tsx (L99-110)
```typescript
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

**File:** packages/api/src/utils/toBech32m.ts (L11-14)
```typescript
export default function toBech32m(value: string, prefix: string): string {
  if (value.startsWith(prefix)) {
    return value;
  }
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
