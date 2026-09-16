### Title
Fixed-denomination assets sent to an AA become permanently and irrecoverably locked - ([File: aa_composer.js])

### Summary
Any unprivileged unit poster who sends a payment of a `fixed_denominations` asset to an Autonomous Agent (AA) as a trigger causes those funds to be absorbed into the AA's balance with no possible way for the AA — or anyone else — to ever pay them back out, because the AA response-composer unconditionally strips any outgoing payment message denominated in a `fixed_denominations` asset.

### Finding Description
When an AA's trigger-handling code composes its response messages in `sendUnit()`, each payment message that references an asset is checked against that asset's properties. If the asset has `fixed_denominations` set, the composer explicitly skips completing the payload for it ("will skip it later") and, in a later pass, removes any payment message for that asset entirely: [1](#0-0) [2](#0-1) 

This is unconditional: there is no way inside AA formula/oscript logic to ever emit a valid outgoing `payment` message for a `fixed_denominations` asset — the composer will always drop such a message. If dropping the message reduces `messages` to zero, the composer treats it as `handleSuccessfulEmptyResponseUnit`, silently "eating" the received coins — the trigger unit is accepted, and any state changes made by the AA up to that point are still committed: [3](#0-2) 

Since `fixed_denominations` assets (created via the `asset` message with `fixed_denominations: true`) are indivisible-denomination assets that any unprivileged asset issuer can define, and the receiving AA has no control over what type of asset a trigger sender chooses to pay in, any user can send such an asset to *any* AA. Once inside the AA's balance, the protocol architecturally forbids the AA from ever returning it: there is no rescue/withdraw code path, no owner override, and no core protocol mechanism to un-stick these funds — unlike ordinary wallets, which can freely spend fixed-denomination assets via `indivisible_asset.js`.

### Impact Explanation
This results in a permanent freezing of funds: any fixed-denomination asset units sent into an AA are irrecoverably lost from the sender's perspective and unusable in general, because the AA can never construct a valid outgoing payment for that asset type. This is analogous to the reported issue — assets can enter a receiving construct (the AA, akin to `RootBridgeRelay.sol`'s `receive()`) with no path to rescue them out, regardless of the AA author's intentions or any privileged action, since the restriction is enforced unconditionally at the protocol/composer level rather than being an AA-author design choice.

### Likelihood Explanation
Likelihood is high in the sense that it requires no special privilege: any user can (1) issue a `fixed_denominations` asset via a standard `asset` definition message, and (2) send a payment of that asset to any AA address as a trigger. No cooperation from the AA author or any hub/witness/validator is needed, and no malicious node/peer/network behavior is required — this is purely a consequence of core protocol logic in `aa_composer.js` triggered by an ordinary asset issuer/trigger-sender interaction.

### Recommendation
Either: (1) reject/bounce triggers that include `fixed_denominations` asset outputs to AAs at validation time (`getTrigger`/`handleTrigger` in `aa_composer.js`) so such funds are never accepted into an AA's balance in the first place, or (2) provide a core-level mechanism allowing AAs (or their formula language) to construct valid outgoing payments for fixed-denomination assets, so that funds mistakenly or intentionally sent to an AA can be forwarded back out.

### Proof of Concept
1. Attacker/user issues a new asset with `fixed_denominations: true` via a standard `asset` message (any unprivileged asset issuer can do this, as shown in `test/samples/create_an_asset.oscript` patterns).
2. User sends a trigger unit paying this fixed-denomination asset to an existing AA (e.g., a bouncer/vault-style AA that is coded to forward back any asset it receives, such as the `sell_asset_for_bytes.oscript`/`a_bank_without_percent.oscript`-style samples).
3. In `handleTrigger` → `sendUnit`, when the AA composes its outgoing payment message for that asset, `aa_composer.js` line 1327 detects `objAsset.fixed_denominations` and skips completing the payload; the later filter at line 1356 removes the payment message entirely.
4. If no other messages remain, `handleSuccessfulEmptyResponseUnit(null)` is invoked (line 1360) — the trigger unit and any state changes are accepted as successful, and the fixed-denomination asset balance is now permanently held by the AA with no code path ever able to pay it out. [4](#0-3)

### Citations

**File:** aa_composer.js (L1323-1361)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
			},
			function (err) {
				if (err)
					return bounce(err);
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
				if (messages.length === 0) {
					error_message = 'no messages after removing 0-outputs (2nd pass)';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```
