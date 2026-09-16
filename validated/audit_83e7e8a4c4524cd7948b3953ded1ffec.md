### Title
Spoofable `payment_notification` allows an unprivileged peer to falsely claim credit for someone else's public payment - ([File: wallet.js])

### Summary
The nkpaymentcap incident relied on the DApp trusting a client-supplied "deposit/transfer" notification instead of independently verifying who actually sent the funds, letting the attacker claim credit for value it never sent. `ocore`'s device-chat handler for the `payment_notification` subject has the same trust flaw: it lets any paired device peer claim authorship of an arbitrary already-existing public unit, and the wallet layer reports that unit as "received from" that peer without checking that the claiming address is actually one of the unit's authors or that the payment was intended for that peer.

### Finding Description
In `wallet.js`, `handleMessageFromHub` processes the `payment_notification` subject as follows: [1](#0-0) 

The code comment itself documents the weakness: *"since the payments are public, an evil user might notify us about a payment sent by someone else (we'll be fooled to believe it was sent by the evil user). It is only possible if he learns our address."* The handler only validates that `unit` is a well-formed hash string, then looks the unit up and, once found, calls `emitNewPublicPaymentReceived(from_address, objJoint.unit, current_message_counter)` — associating the (already-existing, already-validated) unit with whatever `from_address` sent the chat notification, with **no check that `from_address` is among the unit's authors, nor that any output in the unit is actually payable to/expected from that counterparty**.

Because `from_address` is simply the device-chat correspondent's claimed identity (any paired device can message any other paired device it has exchanged a pairing code with), an attacker who merely observes a real public payment on the DAG (unit hashes are public, and any exchange/merchant that publishes a receiving address to solicit payments is explicitly named in the very comment as an at-risk scenario) can send a `payment_notification` for that unit and be credited by any downstream consumer of `new_public_payment_received` as if they were the payer — the same "spoofed transfer notification" pattern as the nkpaymentcap case, where a service credits an account based on an easily-forgeable notification event rather than actually verifying which party is entitled to the credit.

### Impact Explanation
Any bot/merchant/exchange integration on top of `ocore` that listens for `new_public_payment_received` (or any downstream "payment received" wallet event derived from `payment_notification`) to credit a user's balance, unlock content, or confirm an order can be tricked into crediting the wrong (attacker-controlled) account for a legitimate third party's payment — a form of unauthorized value attribution/fund diversion analogous to the EOS fake-notification drain, reachable from an unprivileged paired-device peer with no special privilege other than knowing the recipient's public address and a broadcast unit hash.

### Likelihood Explanation
The attack requires only: (1) a paired-device connection to the target wallet/service (trivial via a shared pairing link/QR code that many wallet-integrated merchant flows publish openly), and (2) knowledge of a real, already-broadcast public payment unit hash sent to the target's address by someone else (unit hashes and payments on the DAG are public). Both conditions are explicitly acknowledged as realistic in the surrounding code comment, and no additional protocol-level protection (e.g., checking `from_address` against `objJoint.unit`'s authors) is implemented in this handler.

### Recommendation
In the `payment_notification` handler, before emitting `emitNewPublicPaymentReceived`, verify that `from_address` is actually one of the unit's authors (`objJoint.unit.authors`) and/or that an output of the unit pays the merchant's specific (ideally one-time) receiving address for the expected amount, rather than trusting the claimed sender identity unconditionally. Document/enforce that consumers of `new_public_payment_received` must not treat the notified `from_address` as authoritative proof of payment source without this author check.

### Proof of Concept
1. Attacker M and honest payer P are both paired with merchant wallet W (M can pair via a publicly shared pairing code, as is common for support/sales chat).
2. P sends a normal public payment to W's address in unit U (visible on-chain).
3. Before or instead of P notifying W, M sends `{"subject":"payment_notification","body":"<U>"}` to W via the device-chat protocol.
4. `wallet.js` handler at lines 426-453 looks up U, finds it, and calls `emitNewPublicPaymentReceived(M_address, U, ...)`, i.e., W's event system now believes M (not P) sent the payment in U.
5. Any bot/service built on W's wallet code that credits the "notifying" `from_address` for the payment in U credits M instead of P, letting M claim goods/services/tokens paid for by P — reproducing the nkpaymentcap "fake transfer notification" profit pattern.

Note: I could not fully trace every downstream consumer of `emitNewPublicPaymentReceived`/`new_public_payment_received` within the indexed portion of the codebase (the emitter function definition and all its listeners were not fully retrievable due to index/tool limits), so the exact severity depends on how a given deployment's exchange/merchant bot consumes this event; a Devin session with full repo access would be needed to enumerate all consumers and confirm end-to-end fund-crediting logic.

### Citations

**File:** wallet.js (L426-453)
```javascript
			case 'payment_notification':
				// note that since the payments are public, an evil user might notify us about a payment sent by someone else 
				// (we'll be fooled to believe it was sent by the evil user).  It is only possible if he learns our address, e.g. if we make it public.
				// Normally, we generate a one-time address and share it in chat session with the future payer only.
				var current_message_counter = ++message_counter;
				var unit = body;
				if (!ValidationUtils.isStringOfLength(unit, constants.HASH_LENGTH))
					return callbacks.ifError("invalid unit in payment notification");
				var bEmitted = false;
				var emitPn = function(objJoint){
					if (bEmitted)
						return;
					bEmitted = true;
					emitNewPublicPaymentReceived(from_address, objJoint.unit, current_message_counter);
				};
				eventBus.once('saved_unit-'+unit, emitPn);
				storage.readJoint(db, unit, {
					ifNotFound: function(){
						console.log("received payment notification for unit "+unit+" which is not known yet, will wait for it");
						callbacks.ifOk();
					},
					ifFound: function(objJoint){
						emitPn(objJoint);
						eventBus.removeListener('saved_unit-'+unit, emitPn);
						callbacks.ifOk();
					}
				});
				break;
```
