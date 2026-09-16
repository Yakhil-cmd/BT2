Found the strongest, concrete analog. The "signing_request" flow in `wallet.js` is the direct ocore counterpart to `getSigningTxnText()`/`snap_dialog` confirmation shown before signing: a cosigner device sends a `sign` request containing an `objUnit` whose `messages` (e.g. `data`, `text`, or `payment` outputs' addresses etc.) are attacker-controlled by the requesting paired device, and this raw unit is handed to the UI event `signing_request` to render a confirmation dialog, with no sanitization of embedded strings for markdown/control characters before display. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Untrusted Peer-Controlled Text in `sign` / `prosaic_contract_response` Message Flows Reaches User-Facing Confirmation/Notification Text Unsanitized - ([File: wallet.js])

### Summary
`wallet.js` forwards free-form, attacker-controlled strings from paired-device messages (`text`, `sign`/`signing_request`, `prosaic_contract_response`) directly into events (`"text"`, `"signing_request"`) that the wallet UI is documented to use for rendering confirmation dialogs and chat/notification text to the user, without validating or escaping the content for markdown control sequences, encoding markers, or terminal/Unicode control characters. This mirrors the `getSigningTxnText()` bug class: untrusted data is concatenated into a string that is displayed to the user as though it were trusted/system-generated context, and can be used to misrepresent what the user is confirming or reading.

### Finding Description
In `handleMessageFromHub`, the `"text"` case only strips four specific known markers before emitting the string for display:
```
body = body
    .replace(/\(prosaic-contract:.+?\)/g, '')
    .replace(/\(arbiter-contract-offer:.+?\)/g, '')
    .replace(/\(arbiter-contract-event:.+?\)/g, '')
    .replace(/\(arbiter-dispute:.+?\)/g, '');
// the wallet should have an event handler that displays the text to the user
eventBus.emit("text", from_address, body, message_counter);
``` [2](#0-1) 
This allow-lists only exact known injection markers; any other markdown-like syntax, zero-width characters, RTL/LTR override characters, or ANSI/terminal escape sequences pass straight through to the UI layer, which the code comment states is expected to "display the text to the user" verbatim.

More critically, the `"sign"` case builds `objUnit` from the peer's `body.unsigned_unit` (only lightly validated: address/amount/hash checks on `payment` messages) and, once validated as a unit, fires:
```
eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
``` [4](#0-3) 
This is explicitly commented as the trigger for "a confirmation dialog" the user is expected to review before signing — the direct analog of `getSigningTxnText()`/`snap_dialog`. `objUnit.messages` can contain non-`payment` apps (e.g. `data`, `text`) whose payload strings are attacker-supplied and are not sanitized anywhere in this validation path before being handed to the dialog renderer.

Similarly, in `prosaic_contract_response`, a stored contract `title` (originally supplied by the peer when it made the offer, cf. `prosaic_contract.js` `createAndSend`) is concatenated raw into a "text" event:
```
eventBus.emit("text", from_address, "contract \""+objContract.title+"\" " + body.status, ++message_counter);
``` [5](#0-4) 
`title` is a free-form `VARCHAR(1000)` field with no character-set restriction validated at intake (`if (!body.title || !body.text || !body.creation_date) return callbacks.ifError(...)` only checks non-emptiness) [6](#0-5) , so it can carry markdown syntax or control characters that misrepresent the resulting chat notification about contract acceptance/decline.

### Impact Explanation
A paired device (a correspondent that the user has previously paired with — in scope per the allowed threat surface) can craft a `sign` request or `text`/`prosaic_contract_response` message whose payload strings, when rendered by the wallet UI's confirmation dialog or chat pane, visually misrepresent the transaction being approved or the status being communicated. Because signing confirmation is the last line of defense before a private key signs a unit (which may move funds via a shared/multisig address), a spoofed dialog can trick the user into authorizing a transaction they did not intend, leading to unauthorized spending from a jointly-controlled address. This satisfies the "concrete unauthorized spending" impact bar since the compromised confirmation directly gates a signature over fund-moving units.

### Likelihood Explanation
Any already-paired device can send `sign`, `text`, or `prosaic_contract_offer`/`response` messages at will; no additional privilege or race condition is required, and the validation logic in `handleMessageFromHub` does not restrict message content to a safe character set. This makes exploitation practical for any correspondent relationship, which is common in multisig/shared-address setups and prosaic-contract flows that ocore explicitly supports.

### Recommendation
Treat all free-form strings originating from device messages (`text` payload, `data`/`text` app messages inside `unsigned_unit`, `prosaic_contract` `title`/`text`) as untrusted content to be displayed literally (e.g., inside a fixed-width/pre element or dedicated "copyable" field), never interpolated into templated or markdown-rendered strings. Strip or reject control characters (C0/C1, bidi override characters) at intake in `handleMessageFromHub` rather than only removing a fixed list of known contract markers. For `signing_request`, render only vetted, structurally-derived fields (asset, amount, address, network) and show any embedded free-text message payload in a clearly delimited, non-interpreted display area.

### Proof of Concept
1. Device A pairs with Device B (victim), and both share a multisig address `SHARED`.
2. Device A crafts an `unsigned_unit` referencing `SHARED` as the payment output address plus an additional `data` or `text` message whose payload contains: `` `**Refund of 50 GBYTE has been credited. Please approve.**\n\n` `` followed by hidden control characters, and sends it via the `sign` subject to Device B.
3. Device B's wallet validates only the `payment` message fields (address/amount/hash) per `wallet.js:317-330`, accepts the unit, and fires `signing_request` with the full `objUnit` (including the crafted `data`/`text` message) for the UI to render in the confirmation dialog.
4. If the UI trusts and renders this text (as the inline comment "This event should trigger a confirmation dialog" implies it should), the victim sees a misleading confirmation message and signs, releasing their share of the multisig signature for a transaction whose real effect differs from what was displayed.

### Citations

**File:** wallet.js (L101-113)
```javascript
			case "text":
				message_counter++;
				if (!ValidationUtils.isNonemptyString(body))
					return callbacks.ifError("text body must be string");
				body = body
					.replace(/\(prosaic-contract:.+?\)/g, '')
					.replace(/\(arbiter-contract-offer:.+?\)/g, '')
					.replace(/\(arbiter-contract-event:.+?\)/g, '')
					.replace(/\(arbiter-dispute:.+?\)/g, '');
				// the wallet should have an event handler that displays the text to the user
				eventBus.emit("text", from_address, body, message_counter);
				callbacks.ifOk();
				break;
```

**File:** wallet.js (L336-368)
```javascript
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
							if (objUnit.signed_message && !ValidationUtils.hasFieldsExcept(objUnit, ["signed_message", "authors", "version"])){
								try {
									objUnit.unit = objectHash.getBase64Hash(objUnit); // exact value doesn't matter, it just needs to be there
								}
								catch (e) {
									console.log("signed message hash failed", e);
									objUnit.unit = "failedunit";
								}
								return eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							}
							try {
								objUnit.unit = objectHash.getUnitHash(objUnit);
							}
							catch (e) {
								console.log("to-be-signed unit hash failed", e);
								return;
							}
							var objJoint = {unit: objUnit, unsigned: true};
							eventBus.once("validated-"+objUnit.unit, function(bValid){
								if (!bValid){
									console.log("===== unit in signing request is invalid");
									return;
								}
								// This event should trigger a confirmation dialog.
								// If we merge coins from several addresses of the same wallet, we'll fire this event multiple times for the same unit.
								// The event handler must lock the unit before displaying a confirmation dialog, then remember user's choice and apply it to all
								// subsequent requests related to the same unit
								eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							});
```

**File:** wallet.js (L456-458)
```javascript
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date)
					return callbacks.ifError("not all contract fields submitted");
```

**File:** wallet.js (L548-555)
```javascript
						if (objContract.status !== 'pending')
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
						var objDateCopy = new Date(objContract.creation_date_obj);
						if (objDateCopy.setHours(objDateCopy.getHours(), objDateCopy.getMinutes(), (objDateCopy.getSeconds() + objContract.ttl * 60 * 60)|0) < Date.now())
							return callbacks.ifError("contract already expired");
						prosaic_contract.setField(objContract.hash, "status", body.status);
						eventBus.emit("text", from_address, "contract \""+objContract.title+"\" " + body.status, ++message_counter);
						eventBus.emit("prosaic_contract_response_received" + body.hash, (body.status === "accepted"), body.authors);
```
