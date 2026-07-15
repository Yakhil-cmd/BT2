### Title
Attacker-Controlled `puzzleHash` in Blockchain Notifications Spoofs Counter-Offer Destination — (File: `packages/gui/src/hooks/useBlockchainNotifications.tsx`)

### Summary
An unprivileged attacker can send a blockchain notification to any wallet address with an arbitrary `puzzleHash` (the sender's return address). The GUI trusts this field without validation and propagates it as the counter-offer destination throughout the offer flow. When the victim clicks "Counter" on the notification, the counter-offer builder and subsequent sharing dialog are silently pre-populated with the attacker's address. The victim may unknowingly dispatch their counter-offer notification to the attacker, who can then accept it and receive the victim's assets.

### Finding Description

**Step 1 — Attacker-controlled `puzzleHash` stored without validation.**

In `useBlockchainNotifications.tsx`, the `ph` field is read verbatim from the attacker-crafted on-chain message and stored in the notification object:

```js
const { u: url, ph: puzzleHash } = data;
if (puzzleHash) {
  return {
    type: NotificationType.OFFER,
    id,
    source: 'BLOCKCHAIN',
    timestamp: timestampData.timestamp,
    offerURL: url,
    puzzleHash,          // ← fully attacker-controlled, no validation
  };
}
``` [1](#0-0) 

**Step 2 — `puzzleHash` gates and populates the "Counter" action.**

In `OfferIncomingTable.tsx`, the presence of `puzzleHash` enables the Counter button, and its value is converted to a bech32m address that is forwarded to the offer builder as the counter-offer destination:

```js
const counterDisabled = !puzzleHash || isDl;
// ...
const address = currencyCode && puzzleHash
  ? toBech32m(puzzleHash, currencyCode.toLowerCase())
  : '';
navigate('/dashboard/offers/builder', {
  state: { referrerPath: location.pathname, isCounterOffer: true, address, offer },
});
``` [2](#0-1) [3](#0-2) 

The same propagation occurs in `OfferBuilderViewer.tsx` when the user clicks "Counter Offer" from the offer view screen: [4](#0-3) 

**Step 3 — Attacker's address silently pre-fills the sharing dialog.**

When the victim finishes building the counter-offer and opens the share dialog, `OfferShareDialog` receives the attacker's `address` and passes it to `NotificationSendDialog`. The address field is rendered as a **disabled** (non-editable) text field labelled "Notification recipient's address":

```jsx
<TextField
  variant="filled"
  name="address"
  label={<Trans>Address</Trans>}
  disabled          // ← user cannot correct it
  fullWidth
/>
``` [5](#0-4) 

The victim sees a long bech32m string they did not choose and cannot change. Because they have no prior knowledge of the legitimate offer creator's address, they are unlikely to detect the substitution.

### Impact Explanation

The attacker receives the victim's counter-offer notification and can accept it on-chain, receiving the victim's offered assets (XCH, CAT, NFT). This matches the allowed High impact: *"corruption of notification state that causes a user to send to the wrong destination."* The victim's assets are transferred to the attacker without the victim's informed consent.

### Likelihood Explanation

- Any unprivileged actor can send a blockchain notification to any address for a small fee (the `send_notification` RPC is publicly accessible).
- The `puzzleHash` field is never validated against any known address or the offer's actual creator.
- The destination address field in the sharing dialog is disabled, preventing the user from correcting it.
- Users have no baseline to compare the pre-filled address against, making detection unlikely in practice.
- The victim must manually click Counter, build, and share the offer — this is the only friction reducing likelihood.

### Recommendation

1. **Validate `puzzleHash` format** in `useBlockchainNotifications.tsx` before storing it (e.g., verify it is a valid 32-byte hex puzzle hash).
2. **Display a prominent warning** in `NotificationSendDialog` when the recipient address originates from an external notification payload rather than from the user's own address book or a verified source.
3. **Allow the user to edit or confirm** the destination address before sending, rather than rendering it as a disabled field.

### Proof of Concept

1. Attacker calls `send_notification` targeting the victim's puzzle hash, embedding a JSON payload `{"v":1,"t":1,"d":{"u":"https://dexie.space/offers/...", "ph":"<attacker_puzzle_hash>"}}`.
2. Victim's GUI receives the notification via `useGetNotificationsQuery` → `useBlockchainNotifications` → stores `puzzleHash = attacker_puzzle_hash`.
3. Victim sees "You have a new offer" and clicks **Counter**.
4. `OfferIncomingTable.handleCounterOffer` converts `attacker_puzzle_hash` to bech32m and navigates to `/dashboard/offers/builder` with `address = attacker_bech32m_address`.
5. Victim builds a counter-offer (e.g., offering their NFT for 10 XCH) and proceeds to share.
6. `NotificationSendDialog` opens with the attacker's address pre-filled and disabled.
7. Victim clicks **Send Message** — the counter-offer notification is delivered to the attacker.
8. Attacker accepts the counter-offer on-chain, receiving the victim's NFT.

### Citations

**File:** packages/gui/src/hooks/useBlockchainNotifications.tsx (L98-119)
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
                }

                return {
                  type: NotificationType.OFFER,
                  id,
                  source: 'BLOCKCHAIN',
                  timestamp: timestampData.timestamp,
                  offerURL: url,
                };
```

**File:** packages/gui/src/components/offers2/OfferIncomingTable.tsx (L79-79)
```typescript
      const counterDisabled = !puzzleHash || isDl;
```

**File:** packages/gui/src/components/offers2/OfferIncomingTable.tsx (L186-206)
```typescript
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

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L219-229)
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
