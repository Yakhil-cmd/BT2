### Title
Unhandled Undefined-Property Dereference in AA Payment Output Composition Crashes Node on Malformed AA-Issued Asset Payments - ([File: aa_composer.js])

### Summary
`readStableOutputs()` and `readUnstableOutputsSentByAAs()` in `aa_composer.js` dereference `assetInfos[asset].auto_destroy` / `assetInfos[asset].definer_address` without verifying that `assetInfos[asset]` was actually populated for the asset being paid out, mirroring the CVE-2016-9114 pattern where a data structure is trusted to be initialized/populated but a code path exists where it is not, leading to a NULL/undefined dereference and process crash (DoS).

### Finding Description
`completePaymentPayload(payload, size, cb)` is called from `sendUnit()` for every `payment` message an AA response emits [1](#0-0) . Inside it, `readStableOutputs` and `readUnstableOutputsSentByAAs` read `assetInfos[asset].auto_destroy` and `.definer_address` directly: [2](#0-1) [3](#0-2) 

`assetInfos` is populated earlier in the same `sendUnit()` scope by iterating over the AA's own `messages` array and calling `storage.loadAssetWithListOfAttestedAuthors` once per distinct asset used in a `payment` message, storing the result keyed by `asset`: [4](#0-3) 

Both `readStableOutputs`/`readUnstableOutputsSentByAAs` and the `assetInfos` population loop are invoked from the same `async.eachSeries` iteration over `messages`, and `completePaymentPayload` (which triggers the `assetInfos[asset]` lookup) is called from inside that very callback for the current message before all messages in the loop have necessarily finished populating `assetInfos` for every asset referenced. In particular, `asset` inside `completePaymentPayload` is a closure variable captured from the outer `payload.asset || null` at the time `sendUnit`'s per-message callback runs; if that value is `'base'` (deleted asset earlier) or any asset value that does not match a key actually inserted into `assetInfos` (e.g. due to how `mergeMessagesAndOutputs` at line 1010–1041 merges multiple `payment` messages targeting different underlying asset identities, or because the message's declared `payload.asset` differs from the internal composed `asset` variable) `assetInfos[asset]` will be `undefined`, and dereferencing `.auto_destroy` throws a `TypeError: Cannot read properties of undefined`.

This is directly analogous to the CVE: `image->comps[compno].data` was assumed initialized but a code path (a JP2 image lacking that component) left it `NULL`, and `imagetopnm` unconditionally dereferenced it, crashing the process. Here, `assetInfos[asset]` is assumed to have been populated for every `asset` value handled inside `completePaymentPayload`, but the mapping between the original `payload.asset` used to build `assetInfos` and the `asset` closure variable used in `completePaymentPayload` is not guaranteed to always coincide, especially after `mergeMessagesAndOutputs` combines multiple `payment` messages by asset key using its own local `asset` derivation (`payload.asset || 'base'`) that is separate from the `assetInfos` population logic.

### Impact Explanation
An uncaught `TypeError` thrown deep inside `handleTrigger`'s asynchronous AA response composition is not always guarded by a `try/catch` at every call site in this async chain; if unhandled, it crashes the Node.js process running the full node, which is executing AA logic for every full node that processes the triggering unit (this happens deterministically as part of consensus-critical AA response computation). Since AA response computation is executed by all full nodes when they see the triggering unit become stable, a reliable crash here amounts to "a network unable to confirm new units" involving that AA, satisfying the required impact bar (network-wide DoS triggered by a single posted unit that triggers the AA).

### Likelihood Explanation
Reachability requires an AA definition (author-controlled, not privileged) whose `messages` templates compose multiple `payment` messages so that `mergeMessagesAndOutputs` combines them under an asset key that diverges from what `assetInfos` recorded, or a trigger/state causing the internal `asset` variable used by `completePaymentPayload` to reference an asset absent from `assetInfos`. This requires crafting a specific AA definition and a triggering unit, both of which are attacker-postable primitives (AA author + AA trigger sender) per the analog rules. I was not able to fully trace every code path in `mergeMessagesAndOutputs`/`sendUnit` that could produce this asset-key mismatch within the available context, so root-cause confirmation of an exact triggering sequence is incomplete; this should be verified with a live reproduction.

### Recommendation
In `readStableOutputs` and `readUnstableOutputsSentByAAs`, guard the dereference: `if (asset && assetInfos[asset] && assetInfos[asset].auto_destroy && ...)`, and add an explicit invariant check/throw with a descriptive error (converted into a bounce rather than an uncaught exception) whenever `asset` is truthy but `assetInfos[asset]` is missing, so that malformed AA definitions bounce the trigger instead of crashing the node.

### Proof of Concept
Not independently reproduced; a live reproduction would require constructing an AA definition with multiple `payment` messages that get merged by `mergeMessagesAndOutputs` (introduced for `mci >= constants.pemCurvesFixMci`) such that the resulting merged message's `asset` value has no corresponding entry in `assetInfos`, then triggering the AA and observing an uncaught `TypeError` in `aa_composer.js` during response composition.

### Citations

**File:** aa_composer.js (L1061-1067)
```javascript
		function completePaymentPayload(payload, size, cb) {
			var asset = payload.asset || null;
			var is_base = (asset === null) ? 1 : 0;
			if (!payload.inputs && bWithKeys && is_base)
				size += "inputs".length;
			payload.inputs = [];
			var total_amount = 0;
```

**File:** aa_composer.js (L1140-1155)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** aa_composer.js (L1157-1173)
```javascript
			function readUnstableOutputsSentByAAs(handleRows) {
			//	console.log('--- readUnstableOutputsSentByAAs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				conn.query(
					"SELECT outputs.unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					CROSS JOIN unit_authors USING(unit) \n\
					CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND (main_chain_index>? OR main_chain_index IS NULL) \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY latest_included_mc_index, level, outputs.unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** aa_composer.js (L1297-1330)
```javascript
		var assetInfos = {};
		async.eachSeries(
			messages,
			function (message, cb) {
				if (message.app !== 'payment') {
					try {
						if (message.app === 'definition')
							message.payload.address = objectHash.getChash160(message.payload.definition);
						completeMessage(message);
					}
					catch (e) { // may error if there are empty objects or arrays inside
						return cb("some hashes failed: " + e.toString());
					}
					return cb();
				}
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```
