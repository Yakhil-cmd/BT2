### Title
Private assets sent to an Autonomous Agent are permanently locked with no possible withdrawal path - (File: aa_composer.js)

### Summary
This is the ocore analog of the "locked assets in contracts" bug class: `Comet`/`Bulker` accept ETH they cannot later release; here, an Autonomous Agent (AA) can be made to receive/register a private-asset balance that the AA protocol itself can never spend back out, because AA-authored units are categorically forbidden from including `spend_proofs`, which private-asset payments require. Any unprivileged asset issuer or ordinary user can trigger this by simply paying a private asset to any AA address.

### Finding Description
`getTrigger()` builds `trigger.outputs` directly from the payment message outputs addressed to the AA [1](#0-0) , and `updateInitialAABalances()` credits this into the AA's persistent `aa_balances` for both the real-DB path and the estimation (`bAir`) path [2](#0-1) . Nothing in this flow distinguishes a private asset from a public one when accepting the incoming balance.

Once that balance exists, the AA has no way to ever spend it out again. When building an AA response unit, `sendUnit()` explicitly refuses to construct payment messages for private assets: `if (objAsset.is_private) return cb("sending private asset from AA");` [3](#0-2) . This is because sending a private asset requires `spend_proofs` in the payment message, and `validateMessage()` unconditionally rejects any message with `spend_proofs` when the author is an AA: `if (objValidationState.bAA) return callback("spend proofs in AA");` [4](#0-3) . There is no sweep/administrative function anywhere in the AA framework (unlike `Comet.approveThis`) that lets any party extract a private-asset balance credited to an AA — an AA's only recovery mechanism is issuing outbound `payment` messages, which is exactly the path that is blocked for private assets.

Any user or the AA's own trigger-data logic cannot prevent this either: acceptance of the payment into `aa_balances` happens unconditionally based on the destination address matching the AA, before any AA-authored business logic runs and irrespective of whether the AA "wants" the asset.

### Impact Explanation
This causes irrecoverable freezing of AA funds: any base-asset amount that accompanies such an operation is also effectively wasted (the trigger still consumes bounce fees / gas), and the private-asset value becomes permanently stuck in `aa_balances`, unreachable by the AA owner/community, by the sender, or by protocol-level recovery. Because this affects every AA in the ecosystem identically (it is a protocol-level gap, not an application bug an AA author can code around), the potential aggregate fund loss scales with adoption of private assets and AAs. This matches the accepted impact category of "AA fund loss or freezing."

### Likelihood Explanation
Likelihood is high: any unprivileged party can issue a private asset (self-service via `asset` message) and send it to any known AA address using an ordinary private payment. No cooperation from the AA definer or witnesses is required, and the condition triggers deterministically every time — it is not a race condition or a rare edge case, it is baked into consensus validation (`spend proofs in AA` rejection) and the AA composer's `sendUnit` guard.

### Recommendation
- Prevent private-asset balances from ever being credited to `aa_balances` in `updateInitialAABalances()`/`getTrigger()` — i.e., either reject/bounce triggers whose payment includes a private asset targeting the AA, or exclude private-asset outputs from `trigger.outputs` entirely so they are never absorbed into the AA's spendable/tracked balance.
- Alternatively, if silent absorption is intentional to avoid griefing via bogus triggers, expose a protocol-level recovery path (analogous to `Comet.approveThis`) allowing the definer (or a formula-controlled address) to redeem/burn a stuck private-asset balance, so funds are not unconditionally lost.
- Add validation-layer messaging so senders are warned/blocked before privately paying assets to an address known to be an AA (`aa_addresses` lookup already exists and is used elsewhere, e.g. `checkAAOutputs()` in `aa_addresses.js`), similar to existing bounce-fee warnings.

### Proof of Concept
1. Attacker issues a private, divisible asset (`app: 'asset'`, `is_private: true`) using ordinary user tooling.
2. Attacker sends a private payment of that asset to any AA address `X` (any deployed AA, chosen arbitrarily; no cooperation from the AA needed).
3. When the triggering unit stabilizes, `getTrigger()` picks up the output addressed to `X` and `updateInitialAABalances()` credits it into `aa_balances` for asset A at address `X` [2](#0-1) .
4. The AA’s own response logic (or any subsequent AA logic) that attempts `{app: 'payment', payload: {asset: A, outputs: [...]}}` to move this balance out is rejected during message assembly with `"sending private asset from AA"` [3](#0-2) ; even a hand-crafted AA-authored unit with `spend_proofs` would fail consensus validation with `"spend proofs in AA"` [4](#0-3) .
5. The credited private-asset balance now sits permanently in `aa_balances` for address `X` with no code path in ocore that can ever move it out again.

### Citations

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
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

**File:** validation.js (L1539-1543)
```javascript
	if ("spend_proofs" in objMessage){
		if (objValidationState.bAA)
			return callback("spend proofs in AA");
		if (objMessage.app !== "payment")
			return callback("spend proofs in non-payment message");
```
