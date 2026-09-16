Based on my investigation, I found a solid analog in the `ocore` codebase for this bug class.

### Title
Fixed-denomination (indivisible) assets deposited into an AA become permanently and irrecoverably stuck - (File: `aa_composer.js`)

### Summary
An Autonomous Agent (AA) can receive any asset via a trigger payment, and the amount is unconditionally credited to the AA's internal `aa_balances` for that asset. However, when the AA's oscript logic later attempts to pay that balance back out in a response, `ocore` silently strips any payment message denominated in a `fixed_denominations` (indivisible) asset before the response unit is built. There is no oscript primitive that lets an AA select specific indivisible coins/denominations (unlike a wallet, which uses `pickIndivisibleCoinsForAmount`), so an AA can never construct a valid transfer of such an asset. This mirrors the `VaultBooster.deposit` issue: a contract-like recipient accepts a token type it has no mechanism to hand back, permanently trapping user funds.

### Finding Description
When a trigger sends a payment to an AA, `getTrigger()` records all output amounts into `trigger.outputs` regardless of asset type, and `updateInitialAABalances()` credits every such asset (including fixed-denomination ones) into `aa_balances` with no distinction. [1](#0-0) 

Later, when the AA tries to construct payment response messages in `sendUnit()`, each payment message is checked against `storage.loadAssetWithListOfAttestedAuthors`, and if `objAsset.fixed_denominations` is true, the message is deferred ("will skip it later") rather than completed: [2](#0-1) 

After the first pass, any payment message still referencing a `fixed_denominations` asset is unconditionally filtered out of the final response unit: [3](#0-2) 

If this filtering removes all messages, the AA silently "eats" the trigger's coins with no response at all (`handleSuccessfulEmptyResponseUnit`), while the credited balance for that asset remains permanently in `aa_balances`, unreachable by any oscript payment primitive. The comment `// will skip it later` and the log line `'no messages after removing fixed denominations'` confirm this is a structural limitation, not an incidental bug: the AA composer has no code path that builds indivisible-asset payment messages, contrasting with wallet-side transfers which use `indivisible_asset.js`'s `pickIndivisibleCoinsForAmount()`/`composeIndivisibleAssetPaymentJoint()` to select correct coin denominations and change outputs — logic entirely absent from `aa_composer.js`. [4](#0-3) 

### Impact Explanation
Any user or asset issuer who defines an asset with `fixed_denominations: true` (e.g. NFT-like or fixed-denomination indivisible coins) and sends it to any AA (whether by mistake, or because the AA's `messages` reference `trigger.output[[asset=...]]` expecting to route it back) will lose access to those funds permanently. The AA's oscript author cannot pay it out even if they intentionally write a payment message with `asset: "{trigger.data.asset}"`, because `sendUnit()` always drops such messages before finalizing the response unit. This is a fund-freezing condition within the AA — a listed acceptable-impact category — with no owner/definer-level recovery mechanism in the protocol itself.

### Likelihood Explanation
Likelihood is high in practice: any indivisible/fixed-denomination asset (which is a fully supported, validator-defined asset type in `ocore`, see `validateAssetDefinition` in `validation.js`) sent as a trigger payment to an AA is affected without requiring any attacker action — it is a deterministic consequence of the protocol design whenever such a payment occurs, whether from user error, a poorly-written AA definition that shows a `messages` case referencing arbitrary `trigger.data.asset`, or a malicious actor tricking a user/AA author into believing the asset is retrievable.

### Recommendation
Either (a) reject/bounce trigger payments containing `fixed_denominations` assets to AAs at validation time so users cannot deposit an asset type the AA can never return, or (b) implement AA-side coin-selection logic (analogous to `pickIndivisibleCoinsForAmount`) so response messages paying fixed-denomination assets can be correctly constructed instead of being silently filtered out.

### Proof of Concept
1. Define an asset with `fixed_denominations: true` and `denominations` (e.g., an NFT-style asset), see the accepted fields in `validateAssetDefinition`, `validation.js` lines 2725-2755.
2. Deploy an AA whose oscript includes a case such as: `{ app: 'payment', payload: { asset: "{trigger.data.asset}", outputs: [{address: "{trigger.address}", amount: "{trigger.output[[asset=trigger.data.asset]]}"}] } }` intended to forward back any asset received.
3. Send a trigger unit that pays the fixed-denomination asset to the AA along with `trigger.data.asset` set to that asset id.
4. Observe: `aa_balances` for the AA is credited with the asset amount (`updateInitialAABalances`), but the outgoing payment message is filtered out in `sendUnit()` (`fixed_denominations` check), producing either no response, or a response missing the expected payout — the asset balance remains stuck in `aa_balances` indefinitely with no path to withdraw it.

### Citations

**File:** aa_composer.js (L474-527)
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

**File:** aa_composer.js (L1350-1360)
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
```

**File:** indivisible_asset.js (L391-399)
```javascript
function pickIndivisibleCoinsForAmount(
	conn, objAsset, arrAddresses, last_ball_mci, to_address, change_address, amount, tolerance_plus, tolerance_minus,
	bMultiAuthored, spend_unconfirmed, onDone)
{
	if (!ValidationUtils.isPositiveInteger(amount))
		throw Error("bad amount: "+amount);
	updateIndivisibleOutputsThatWereReceivedUnstable(conn, function(){
		console.log("updatePrivateIndivisibleOutputsThatWereReceivedUnstable done");
		var arrPayloadsWithProofs = [];
```
