### Title
Autonomous Agents can receive fixed-denomination (NFT-like) assets but can never send them back out, permanently freezing them - (File: aa_composer.js)

### Summary
Obyte's indivisible, fixed-denomination assets (`fixed_denominations: true`, denominated coins with fixed `count_coins`/`denomination`, e.g. non-fungible-like collectible units) are the closest analog in ocore to ERC721/ERC1155 NFTs. Just as the Anchor contract in the Sherlock report could receive but had no way to correctly handle/re-transfer NFTs due to missing receiver hooks, an Autonomous Agent (AA) in ocore can freely *receive* fixed-denomination assets as trigger outputs, but `aa_composer.js` unconditionally strips any outgoing `payment` message that tries to send such an asset out of the AA's response unit. There is no way for an AA to ever forward, return, or otherwise dispose of a fixed-denomination asset it holds - it is permanently trapped in the AA's balance.

### Finding Description
When an AA composes its response unit in `sendUnit()` (`aa_composer.js`), for every outgoing payment message the asset is loaded via `storage.loadAssetWithListOfAttestedAuthors`, and if the asset has `fixed_denominations` set, the message is deliberately skipped for further processing: [1](#0-0) 

Then, after all messages are compiled, a second filtering pass removes any remaining payment message whose asset is fixed-denomination, regardless of what the AA's oscript logic intended to send: [2](#0-1) 

If this filtering empties out all messages, the AA silently "eats" the trigger and produces an empty response (`'no messages after removing fixed denominations'`), i.e., the fixed-denomination asset payment is discarded with no error surfaced to the trigger sender: [3](#0-2) 

Meanwhile, nothing prevents an external unit from sending a fixed-denomination asset to an AA address as an ordinary trigger output — `getTrigger()` records outputs for any asset the same way, with no restriction on `fixed_denominations`: [4](#0-3) 

and `updateInitialAABalances`/`updateFinalAABalances` credit the AA's `aa_balances` table for the received asset just like any other asset, with no distinction for fixed-denomination assets: [5](#0-4) 

So the AA's on-chain balance for that fixed-denomination asset increases, but the AA definition language provides no mechanism to construct a payment message capable of moving it back out — every attempt is filtered out before the response unit is built. This is consistent with the restriction that AA-issued assets cannot themselves be `fixed_denominations` (`aa_validation.js`/`validation.js` enforce `issued_by_definer_only === true` implies `fixed_denominations !== true`), but that restriction only concerns assets *issued by* the AA — it does nothing to stop a third party from *sending* an already-existing fixed-denomination asset to the AA, nor does the code allow the AA to ever transfer such an asset onward once received.

### Impact Explanation
This matches the "AA fund loss or freezing" class of impact explicitly in scope. Any AA that is intended to act as a custodian, escrow, marketplace, or pass-through for indivisible/NFT-like assets (the ocore analog of the Anchor "wallet for NFTs" use case) will permanently lock up any such asset sent to it. Users interacting with such an AA lose access to their asset with no recovery path — there is no bounce, no refund, and no way for the AA's oscript logic to reference or move the asset, since every payment message referencing a `fixed_denominations` asset is unconditionally dropped in `sendUnit`. This is a silent, permanent freeze of value with no compensating mechanism (unlike the base-asset bounce-fee/refund path), which is a direct funds-freezing risk for any AA design relying on indivisible assets (NFTs, non-fungible collectibles, tickets, etc.) — a foreseeable design pattern given that ocore natively supports fixed-denomination/indivisible assets as first-class citizens.

### Likelihood Explanation
Likelihood is high for any AA designed to interact with indivisible assets, since:
1. Nothing in unit/trigger validation prevents an unprivileged sender from posting a payment of a fixed-denomination asset to any AA address (`validateAATrigger` in `validation.js` does not special-case `fixed_denominations`).
2. The freezing occurs automatically and silently — the AA developer/documentation would need to actively know about and avoid this limitation, and the trigger sender is never warned before sending.
3. Any oscript AA whose design intends to hold, escrow, resell, or pass through NFT-like assets will hit this immediately upon receiving the first inbound fixed-denomination payment.

### Recommendation
- At minimum, reject/bounce trigger units that send `fixed_denominations` assets to an AA at validation time (in `validateAATrigger`/`getTrigger`), so senders get an explicit failure/refund rather than a silent permanent freeze, mirroring how private assets are already rejected outbound (`"sending private asset from AA"`).
- Preferably, extend the AA payment-message pipeline in `aa_composer.js` (`sendUnit`) to support constructing valid outgoing payment messages for `fixed_denominations` assets (analogous to how `indivisible_asset.js` composes wallet-side indivisible payments), so that AAs can legitimately custody and forward NFT-like assets instead of unconditionally stripping such messages.

### Proof of Concept
1. Deploy an AA whose oscript includes a `payment` message that forwards any asset it receives back to `trigger.address` (e.g., a "bouncer" style AA as in `test/samples/bouncer_infinite_cycle.oscript`).
2. Issue a fixed-denomination asset (`fixed_denominations: true`, e.g. a collectible with `denominations: [{denomination: 1, count_coins: 1}]`) using `indivisible_asset.js` issuance flow.
3. Send a payment of that indivisible asset to the AA's address as a trigger (as permitted by `getTrigger()`/`validateAATrigger`, which impose no restriction on asset type).
4. Observe: `updateInitialAABalances` credits the AA's `aa_balances` for that asset (funds "received"), but in `sendUnit()`, the outgoing payment message referencing that asset is filtered out at [6](#0-5)  and again at [7](#0-6) , resulting in an empty response unit (`'no messages after removing fixed denominations'`) and the asset permanently stuck in the AA's balance with no path to retrieve it.

### Citations

**File:** aa_composer.js (L379-397)
```javascript
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L474-541)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
			}
		);
	}
```

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1350-1361)
```javascript
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
