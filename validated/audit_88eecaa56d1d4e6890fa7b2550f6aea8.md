### Title
Unverified `puzzleHash` in Blockchain Offer Notifications Enables Counter-Offer Destination Spoofing — (`packages/gui/src/hooks/useBlockchainNotifications.tsx`)

---

### Summary

The Chia GUI blockchain notification system parses offer notifications from the chain and trusts the self-reported `puzzleHash` field (`ph`) in the notification payload without any cryptographic verification that it belongs to the actual sender. An unprivileged attacker can send a notification containing a legitimate offer URL but with the attacker's own puzzle hash as the claimed sender address. When the victim clicks "Counter Offer," the GUI silently routes the counter-offer to the attacker's address instead of the legitimate offer maker's address, enabling the attacker to accept the counter-offer and receive the victim's assets.

---

### Finding Description

Blockchain offer notifications are sent on-chain as hex-encoded JSON payloads with the format `{v:1, t:1, d:{u:<offerURL>, ph:<senderPuzzleHash>}}`. The `ph` field is intended to identify the notification sender so the recipient can send a counter-offer back to them.

In `useBlockchainNotifications.tsx`, the GUI decodes this payload and directly trusts the `ph` field:

```typescript
const { u: url, ph: puzzleHash } = data;
// puzzleHash is taken verbatim from the attacker-controlled payload
return {
  type: NotificationType.OFFER,
  id,
  source: 'BLOCKCHAIN',
  timestamp: timestampData.timestamp,
  offerURL: url,
  puzzleHash,   // ← no verification this belongs to the actual sender
};
``` [1](#0-0) 

This `puzzleHash` is then used verbatim as the counter-offer destination in `OfferIncomingTable.tsx`:

```typescript
const address = currencyCode && puzzleHash
  ? toBech32m(puzzleHash, currencyCode.toLowerCase())
  : '';
navigate('/dashboard/offers/builder', {
  state: { isCounterOffer: true, address, offer },
});
``` [2](#0-1) 

The notification format itself documents `ph` as "puzzlehash of the notification sender, for sending a response (counter offer)" — but nothing in the protocol cryptographically binds this field to the actual on-chain sender: [3](#0-2) 

When a legitimate sender creates a notification, they include their own `currentAddress` as the puzzle hash: [4](#0-3) 

There is no on-chain or GUI-side check that the `ph` value in the received notification matches the coin's actual sender puzzle hash.

---

### Impact Explanation

An attacker who sends a blockchain notification to a victim with:
- A valid, whitelisted `offerURL` (pointing to a real offer from a legitimate maker), and
- The attacker's own `puzzleHash` as the `ph` field

causes the victim's GUI to display a seemingly legitimate incoming offer notification. When the victim clicks "Counter Offer," the offer builder is pre-populated with the attacker's address as the counter-offer destination. If the victim completes and the attacker accepts the counter-offer, the victim's assets (XCH, CAT, NFT) are transferred to the attacker.

This matches the **High** impact category: spoofing of notification state that causes a user to send assets to the wrong destination.

---

### Likelihood Explanation

- Sending a blockchain notification costs a small XCH fee but requires no special privileges.
- The attacker only needs to know the victim's wallet address (publicly observable on-chain) and any valid offer URL from a whitelisted service (Dexie, Spacescan, etc.).
- The victim's GUI will display the notification identically to a legitimate one — the offer content is real, only the counter-offer destination is spoofed.
- Users are unlikely to independently verify the counter-offer destination address before submitting.

---

### Recommendation

1. **Verify sender identity**: When parsing a blockchain notification, compare the `ph` field against the actual sender puzzle hash of the notification coin (available from the coin's spend record). Reject or warn if they do not match.
2. **Display the counter-offer destination prominently**: In the counter-offer builder, show the destination address with a clear warning that it came from an unverified notification payload, so users can manually verify before proceeding.
3. **Consider omitting `ph` trust entirely**: Since the puzzle hash cannot be cryptographically verified from the notification payload alone, the counter-offer destination should not be silently pre-filled from it without explicit user confirmation.

---

### Proof of Concept

1. Alice sends a legitimate offer notification to Bob's wallet address, embedding Alice's `puzzleHash` as `ph`.
2. Attacker (Mallory) observes Alice's offer URL on-chain (or independently discovers it from a public offer board).
3. Mallory sends a second blockchain notification to Bob's wallet address with the same `offerURL` but with Mallory's own puzzle hash as `ph`.
4. Bob's GUI shows two notifications for the same offer. Both appear identical in the offer preview (same offer content, same validity).
5. Bob clicks "Counter Offer" on Mallory's notification.
6. `useBlockchainNotifications` sets `puzzleHash` = Mallory's address; `OfferIncomingTable.handleCounterOffer` calls `toBech32m(puzzleHash, ...)` and navigates to the offer builder with `address` = Mallory's address.
7. Bob creates and broadcasts the counter-offer directed to Mallory.
8. Mallory accepts the counter-offer, receiving Bob's assets.

Relevant code path:
- `useBlockchainNotifications.tsx` lines 98–119: parses and trusts `ph` [1](#0-0) 
- `OfferIncomingTable.tsx` lines 175–210: uses `puzzleHash` as counter-offer destination without re-verification [5](#0-4)

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

**File:** packages/gui/src/components/offers2/OfferIncomingTable.tsx (L175-210)
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
    } catch (e) {
      showError(e);
    }
  }
```

**File:** packages/gui/src/components/notification/utils.ts (L12-15)
```typescript
type NotificationOfferData = {
  u: string; // offer URL
  ph?: string; // puzzlehash of the notification sender, for sending a response (counter offer)
};
```

**File:** packages/gui/src/components/notification/NotificationSendDialog.tsx (L119-123)
```typescript
    const targetPuzzleHash = fromBech32m(address);
    const senderPuzzleHash = allowCounterOffer ? fromBech32m(currentAddress) : undefined;
    const amountMojos = chiaToMojo(amount);
    const feeMojos = chiaToMojo(fee);
    const payload = createOfferNotificationPayload({ offerURL, puzzleHash: senderPuzzleHash });
```
