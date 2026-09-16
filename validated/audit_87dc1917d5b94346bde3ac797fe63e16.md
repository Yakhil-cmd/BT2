Based on the investigation, ocore's architecture does not contain a reachable analog to this bug class.

The HyperLiquid bug stems from checking a value (`_vaultEquity()`) that is a **snapshot cached once per EVM block** via a precompile, so multiple transactions within that same block can all read the identical stale value and each independently pass a check meant to be exclusive.

In ocore, the equivalent "shared balance check" scenarios are structurally immune to this class of bug because they don't rely on periodically-refreshed snapshots:

1. **Payment/asset double-spend prevention** relies on live DB state and unique constraints, not a cached snapshot. `validatePaymentInputsAndOutputs` in `validation.js` queries the `outputs`/`inputs` tables directly for each input, and `checkInputDoubleSpend`/`checkForDoublespends` re-check against the current database state for every single unit, backed by DB-level `UNIQUE` constraints (`bySrcOutput`, `byIndexAddress`, `byAssetDenominationSerialAddress`) that make it structurally impossible for two units to consume the same output as "unique" simultaneously. [1](#0-0) [2](#0-1) 

2. **All validation-and-write operations are serialized** through a global write mutex, so there is no window where two transactions can be validated against the same pre-write state and both get committed as valid. `saveJoint` in `writer.js` explicitly acquires `mutex.lock(["write"])`, and locally composed transactions acquire `mutex.lock('handleJoint')` around the entire validate+save flow. [3](#0-2) [4](#0-3) 

3. **AA balance checks are not based on a periodic snapshot either.** `aa_composer.js`'s `handleTrigger` reads the AA's current balance from `aa_balances` at the start of each trigger (`updateInitialAABalances`) and immediately commits the updated balance (`updateFinalAABalances`) before the next queued trigger is processed — triggers are drained from the `aa_triggers` queue one at a time under the same write mutex, so there's no possibility of two triggers seeing the same stale balance and both being allowed to overspend it. [5](#0-4) [6](#0-5) 

4. **Private payment chains** likewise validate spend proofs and output uniqueness against live DB rows (`spend_proofs`, `outputs`) rather than a cached equity/balance figure, and duplicate submissions are explicitly detected and deduplicated in `private_payment.js`. [7](#0-6) 

Since the reachable ocore paths (public payments, AA triggers, private payment chains) all check live, per-transaction database state under a serializing write lock rather than a value cached for the duration of a block, there is no analogous "check bypass via stale cached balance" reachable from an unprivileged unit poster, AA trigger sender, or private-payment counterparty.

### No Vulnerability found for this question.

### Citations

**File:** validation.js (L2258-2270)
```javascript
			function checkInputDoubleSpend(cb2){
			//	if (objAsset)
			//		profiler2.start();
				doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
				if (objAsset){
					doubleSpendWhere += " AND asset=?";
					doubleSpendVars.push(payload.asset);
				}
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
				checkForDoublespends(
```

**File:** initial-db/byteball-mysql.sql (L293-298)
```sql
	address CHAR(32) NOT NULL,
	PRIMARY KEY (unit, message_index, input_index),
	UNIQUE KEY bySrcOutput(src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
	UNIQUE KEY byIndexAddress(type, from_main_chain_index, address, is_unique), -- UNIQUE guarantees there'll be no double spend for type=hc/witnessing
	UNIQUE KEY byAssetDenominationSerialAddress(asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
	KEY byAssetType(asset, type),
```

**File:** writer.js (L24-35)
```javascript
async function saveJoint(objJoint, objValidationState, preCommitCallback, onDone) {
	var objUnit = objJoint.unit;
	console.log("\nsaving unit "+objUnit.unit);
	var arrQueries = [];
	var commit_fn;
	if (objValidationState.conn && !objValidationState.batch)
		throw Error("conn but not batch");
	var bInLargerTx = (objValidationState.conn && objValidationState.batch);
	const bCommonOpList = objValidationState.last_ball_mci >= constants.v4UpgradeMci;

	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** divisible_asset.js (L317-325)
```javascript
		ifOk: async function(objJoint, assocPrivatePayloads, composer_unlock){
			var objUnit = objJoint.unit;
			var unit = objUnit.unit;
			const validate_and_save_unlock = await mutex.lock('handleJoint');
			const combined_unlock = () => {
				validate_and_save_unlock();
				composer_unlock();
			};
			validation.validate(objJoint, {
```

**File:** aa_composer.js (L91-102)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
```

**File:** aa_composer.js (L491-512)
```javascript
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
```

**File:** private_payment.js (L61-103)
```javascript
					// check if duplicate
					var sql = "SELECT address, denomination, amount, blinding FROM outputs WHERE unit=? AND asset=? AND message_index=?";
					var params = [headElement.unit, asset, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
					conn.query(
						sql, 
						params, 
						function(rows){
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
								const stored = rows[0];
								const payload = headElement.payload;
								let bDuplicate = false;
								if (objAsset.fixed_denominations){ // the row we selected is exactly headElement.output_index, filtered in sql above
									const claimed_output = payload.outputs?.[headElement.output_index];
									const revealed_output = headElement?.output;
									bDuplicate =
										ValidationUtils.isNonemptyObject(claimed_output)
										&& ValidationUtils.isNonemptyObject(revealed_output)
										&& stored.denomination === payload.denomination
										&& stored.amount === claimed_output.amount
										&& stored.address === revealed_output.address
										&& stored.blinding === revealed_output.blinding;
								}
								else // divisible outputs are never hidden individually and sql has no output_index filter, so match against any of them
									bDuplicate = (payload.outputs || []).some(output => {
										return ValidationUtils.isNonemptyObject(output)
											&& stored.denomination === 1
											&& stored.amount === output.amount
											&& stored.address === output.address
											&& stored.blinding === output.blinding;
									});
								if (bDuplicate) {
									console.log("duplicate private payment "+params.join(', '));
									return transaction_callbacks.ifOk();
								}
							}
```
