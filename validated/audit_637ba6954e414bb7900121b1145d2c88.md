## Title
Unauthenticated `payment_notification` device message allows fake "top-up" attribution to an arbitrary correspondent - ([File: wallet.js])

### Summary
The LDO report describes a class of bug where a value-transfer signal (a `false` return instead of a revert) can be misinterpreted by downstream consumers as a successful "top-up," enabling a "fake top-up" fraud when the consumer does not independently verify that the claimed sender actually controls the funds. In `ocore`, the `payment_notification` device message handled in `wallet.js` has the analogous property: it lets an unauthenticated correspondent *claim* that a specific already-broadcast, valid public unit was sent by them, and the wallet emits a "received payment" event attributing that unit to `from_address` without checking that `from_address` (or their address) actually authored the payment.

### Finding Description
`handleMessageFromHub`'s `payment_notification` case in [1](#0-0)  reads a `unit` hash supplied by the message body, and — as soon as that unit is known/found — fires `emitNewPublicPaymentReceived(from_address, objJoint.unit, current_message_counter)`. The code contains an explicit developer acknowledgment of the risk: [2](#0-1)  states "an evil user might notify us about a payment sent by someone else (we'll be fooled to believe it was sent by the evil user). It is only possible if he learns our address, e.g. if we make it public."

The only validation performed is that `unit` is a string of the correct hash length (`ValidationUtils.isStringOfLength(unit, constants.HASH_LENGTH)`) and that the unit is actually known/found in storage — there is no check that any output of that unit's `payment` messages actually pays the wallet's own address, nor that `from_address` (the device correspondent) is among the unit's authors or has any real relationship to the payer address. Any device-paired correspondent (or anyone who can be added as a correspondent/chat contact, which is a low-privilege action for a "paired device") can pick an arbitrary already-known unit hash — including a legitimate, unrelated third-party payment that happens to exist on the DAG — and claim credit for it by sending this notification, or can notify the wallet about a self-authored, non-value or dust payment while implying (via UI/consumer logic keyed off `emitNewPublicPaymentReceived`) that a top-up under a specific correspondent occurred.

This mirrors the LDO bug-class root cause: a value/settlement signal is trusted by a receiving party (the wallet UI or any bot/exchange logic subscribed to `new_public_payment_received`) without validating that the claimed counterparty is cryptographically tied to the underlying transfer, opening the door to fraudulent "fake top-up" claims against private-payment/device-message counterparties.

### Impact Explanation
Any downstream integration (e.g., a merchant bot, exchange deposit-detection service, or automated payment-confirmation UI) that relies on the `new_public_payment_received` event to credit or acknowledge a payment from a specific device correspondent can be tricked into crediting the wrong party or crediting a payment that was never actually sent by the claimed correspondent, resulting in unauthorized crediting/fund loss for the receiving party (classic "fake top-up" fraud pattern), which the code comment itself flags but does not fully mitigate (the mitigation relies on the caller keeping the address secret, not on protocol-level verification).

### Likelihood Explanation
Exploitation only requires that the attacker be a paired device correspondent of the victim (an unprivileged interaction reachable via device-message chat, as noted in the code comment itself: "It is only possible if he learns our address"), and that the victim's wallet address has become known to the attacker (e.g., previously shared or observed on-chain, since payments are public). This is a realistic scenario for services that publish deposit addresses or reuse addresses across sessions, making the likelihood moderate.

### Recommendation
Before emitting `new_public_payment_received`/crediting `from_address` for a `payment_notification`, verify the referenced unit actually contains a `payment` message whose author matches `from_address`'s known address (or any address the correspondent controls, if there's an established address-sharing / pairing record), rather than trusting the mere claim in the notification body. Alternatively, treat `payment_notification` strictly as a "wake-up" hint to re-scan one's own outputs and derive the sender independently from validated unit-author/output data, never trusting the `from_address` field for attribution.

### Proof of Concept
1. Attacker pairs their device with the victim's wallet as a normal correspondent (or is already paired) and learns the victim's receiving address (e.g., because it was shared once or reused).
2. Attacker observes any valid, already-broadcast unit on the DAG that pays the victim's address (this can even be a payment originally sent by a completely different, unrelated party).
3. Attacker sends a `payment_notification` device message to the victim with `body = <that unit's hash>`.
4. `wallet.js` `payment_notification` handler at [3](#0-2)  finds the unit and calls `emitNewPublicPaymentReceived(from_address, objJoint.unit, current_message_counter)`, attributing the payment to the attacker's `from_address` even though the attacker never sent it.
5. Any consumer of `new_public_payment_received` (deposit-confirmation bot, chat UI, etc.) credits or acknowledges the payment as coming from the attacker, enabling fraudulent claims of having paid the victim.

### Citations

**File:** wallet.js (L426-452)
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
```
