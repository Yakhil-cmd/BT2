This confirms that ocore does maintain a `temp-bad`/`good`/`final-bad` sequence lifecycle for units at the time they are still unstable, and `temp-bad` units can later resolve to `good` or `final-bad` [1](#0-0) , and conflicting-unit resolution during authoring can flag a unit `temp-bad` even before parents stabilize [2](#0-1) . This validates that unstable data-feed messages carried by such units are not yet final and may later be voided.

### Title
`in_data_feed()`/`dataFeedExists()` accepts unstable oracle data-feed messages without checking unit sequence, unlike `data_feed()` - (File: data_feeds.js)

### Summary
The analog to the report's core flaw ("critical financial logic trusts a value/state that has not been confirmed as final, causing loss when reality diverges from the assumption") exists in ocore's oscript data-feed evaluation used by AAs. `readDataFeedValue()` (backing the `data_feed[[...]]` formula op) explicitly filters out unstable messages from units whose `sequence !== 'good'` before considering them as candidate oracle values [3](#0-2) . In contrast, `dataFeedExists()` (backing the `in_data_feed[[...]]` formula op and the `in data feed` authentifier condition) walks the very same `storage.assocUnstableMessages` set for AA callers but performs no such sequence check [4](#0-3) .

### Finding Description
`dataFeedExists()` is called with `bAA=true` from the `in_data_feed` formula operator when an AA formula evaluates `in_data_feed[[...]]` [5](#0-4) . When `bAA` is true, the function scans `storage.assocUnstableMessages` (all not-yet-stable units, of any sequence) for a matching `data_feed` message from the given oracle addresses, and returns `true` on the first match, with **no filter on `objUnit.sequence`** [6](#0-5) .

Compare this to `readDataFeedValue()`, used by the `data_feed[[...]]` formula op, which explicitly requires `objUnit.sequence === 'good'` before treating a candidate message as valid [3](#0-2) .

Ocore's own consensus model treats units as tentatively `temp-bad` while unstable (due to detected conflicts with sibling units from the same author/oracle), only resolving to `good` or `final-bad` once their MCI stabilizes [1](#0-0) ; a `temp-bad` unit can still be included in `storage.assocUnstableMessages` right up until that resolution [2](#0-1) . This mirrors the report's "collateral seized but not yet finally settled" pattern: `dataFeedExists()`/`in_data_feed()` treats a not-yet-final piece of state as ground truth for a boolean gating decision, while the sibling function that reads the actual value (`data_feed()`) correctly waits for finality.

Because AAs commonly gate fund transfers on boolean predicates like `in_data_feed[[oracles=..., feed_name=..., feed_value=...]]` (e.g., "has the oracle posted X yet?") before releasing funds, and because `bounce()`/response logic executes atomically at trigger time based on this evaluation, an AA can pay out based on an oracle-authored unit that is still `temp-bad` and may later become `final-bad` (i.e., is effectively voided and never becomes part of the canonical history). This is the direct oscript analog of trusting an unconfirmed/soon-to-be-reverted price/state input in the reported bug's stablecoin-liquidation logic.

### Impact Explanation
An AA that uses `in_data_feed[[...]]` to decide whether to execute a payment (a common oracle-gated pattern: escrow release, conditional swap, prediction-market resolution, etc.) can be triggered into paying out funds based on a data-feed unit that never becomes canonical (`final-bad`). Because AA bytes/asset transfers triggered this way are irreversible once the AA's response unit is composed and posted, this can cause a genuine AA fund loss / incorrect payout — the specific class of impact this rules require ("AA fund loss") — without any privileged access; a normal trigger-sender only needs the oracle's near-simultaneous conflicting units (or any circumstance producing a `temp-bad`→`final-bad` unit) to exist in the unstable window at trigger time.

### Likelihood Explanation
Exploitation requires the presence of a `temp-bad` unstable unit carrying a matching data-feed message at the moment the AA trigger unit is processed, which requires either: (a) the oracle (or anyone able to post as one of the listed oracle addresses in a conflicting/double-spending manner) producing two conflicting units in the unstable window, one of which is doomed to `final-bad`, or (b) natural races where a data-feed-posting unit is on a losing fork. This is not attacker-controlled in the fully general case (the AA developer chooses the oracle), but a malicious actor who can post under (or collude with) one of the whitelisted oracle addresses, or simply race timing during oracle unit propagation, can reliably manufacture the `temp-bad` window. Given the deterministic nature of `dataFeedExists`'s unstable-scan behavior (any bAA caller gets it, with no sequence check at all), this is a systematic code-level gap rather than a rare edge case, warranting Medium-to-High likelihood for AAs that rely on `in_data_feed()` for payout gating.

### Recommendation
Add the same `objUnit.sequence !== 'good'` filter used in `readDataFeedValue()` [7](#0-6)  to the `bAA` branch of `dataFeedExists()` [4](#0-3) , so that `in_data_feed[[...]]` cannot return `true` based on a unit that is not (yet) known-`good`. Alternatively, document clearly that `in_data_feed()` results for unstable data may be reverted, and require AA authors to use `data_feed()` (which already excludes non-good sequence) whenever the boolean result gates an irreversible payout.

### Proof of Concept
Conceptual PoC (cannot be executed without network access, but derivable directly from the code paths cited):
1. Deploy an AA `A` whose response logic contains: `if (in_data_feed[[oracles=ORACLE, feed_name='X', feed_value=1]]) { pay funds }`.
2. Have `ORACLE` (or an address behaving as it, e.g. via a compromised/rushed oracle client, or two units racing on the same author before stabilization) post two conflicting units in the same unstable window: one containing `data_feed{X:1}` and a conflicting sibling (double-spending the same inputs) that will resolve to `good`, while the `data_feed{X:1}` unit resolves to `temp-bad` → `final-bad` per `findStableConflictingUnits()`/`markMcIndexStable()` [8](#0-7) .
3. Trigger AA `A` while the `data_feed{X:1}` unit is still unstable (`temp-bad`, not yet resolved). `dataFeedExists()` scans `storage.assocUnstableMessages`, finds the message from an AA-authored unit whose `latest_included_mc_index` is in range, and returns `true` without checking `sequence` [9](#0-8) , causing AA `A` to pay out.
4. After stabilization, the data-feed-carrying unit resolves to `final-bad` and is excluded from canonical history [8](#0-7)  — yet AA `A`'s payout, already executed and posted, is irreversible, resulting in a fund loss/payout that the canonical DAG state never actually supported.

### Citations

**File:** main_chain.js (L1318-1350)
```javascript
	function handleNonserialUnits(){
	//	console.log('handleNonserialUnits')
		conn.query(
			"SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit", [mci], 
			function(rows){
				var arrFinalBadUnits = [];
				async.eachSeries(
					rows,
					function(row, cb){
						if (row.sequence === 'final-bad'){
							arrFinalBadUnits.push(row.unit);
							return row.content_hash ? cb() : setContentHash(row.unit, cb);
						}
						// temp-bad
						if (row.content_hash)
							throw Error("temp-bad and with content_hash?");
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
```

**File:** validation.js (L1304-1341)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
			}
			var arrConflictingUnits = arrConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			breadcrumbs.add("========== found conflicting units "+arrConflictingUnits+" =========");
			breadcrumbs.add("========== will accept a conflicting unit "+objUnit.unit+" =========");
			objValidationState.arrAddressesWithForkedPath.push(objAuthor.address);
			objValidationState.arrConflictingUnits = (objValidationState.arrConflictingUnits || []).concat(arrConflictingUnits);
			bNonserial = true;
			var arrUnstableConflictingUnitProps = arrConflictingUnitProps.filter(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 0);
			});
			// findConflictingUnits() already excludes final-bad rows, so any stable row left here is a real, good competitor
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			// if we are (or already became, due to another author) final-bad, we are not a living competitor for this address either,
			// so there is no need to punish other pending units - they'll correctly resolve to 'good' on their own once stable
			if (objValidationState.sequence === 'final-bad')
				return next();
			if (arrUnstableConflictingUnits.length === 0)
				return next();
			conn.query("SELECT unit FROM units WHERE unit IN(?) AND +sequence='good'",[arrUnstableConflictingUnits],function(rows){
				if (rows.length > 0)
					objValidationState.arrUnitsGettingBadSequence = (objValidationState.arrUnitsGettingBadSequence || []).concat(rows.map(function(row){return row.unit}));
				// we don't modify the db during validation, schedule the update for the write
				objValidationState.arrAdditionalQueries.push(
				{sql: "UPDATE units SET sequence='temp-bad' WHERE unit IN(?) AND +sequence='good'", params: [arrUnstableConflictingUnits]});
				next();
				});
```

**File:** data_feeds.js (L34-53)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
				var feed_value = payload[feed_name];
				if (relation === '=') {
					if (value === feed_value || value.toString() === feed_value.toString())
						bFound = true;
```

**File:** data_feeds.js (L217-224)
```javascript
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.sequence !== 'good')
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
```

**File:** formula/evaluation.js (L701-745)
```javascript
			case 'in_data_feed':
				var params = arr[1];
				var evaluated_params = {};
				async.eachSeries(
					Object.keys(params),
					function(param_name, cb2){
						evaluate(params[param_name].value, function(res){
							if (fatal_error)
								return cb2(fatal_error);
							if (res instanceof wrappedObject)
								res = true;
							if (!isValidValue(res) || typeof res === 'boolean')
								return setFatalError('bad in-df param', { arr }, undefined, cb2);
							if (Decimal.isDecimal(res))
								res = toDoubleRange(res);
							evaluated_params[param_name] = {
								operator: params[param_name].operator,
								value: res
							};
							cb2();
						});
					},
					function(err){
						if (fatal_error)
							return cb(false);
						if (typeof evaluated_params.oracles.value !== 'string')
							return setFatalError('oracles is not a string', { arr }, false, cb);
						var arrAddresses = evaluated_params.oracles.value.split(':');
						if (!arrAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad oracles', { arr }, false, cb);
						var feed_name = evaluated_params.feed_name.value;
						if (!feed_name || typeof feed_name !== 'string')
							return setFatalError('bad feed name', { arr }, false, cb);
						var value = evaluated_params.feed_value.value;
						var relation = evaluated_params.feed_value.operator;
						if (!isValidValue(value))
							return setFatalError("bad feed_value: "+value, { arr }, false, cb);
						var min_mci = 0;
						if (evaluated_params.min_mci){
							min_mci = evaluated_params.min_mci.value.toString();
							if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
								return setFatalError('bad min_mci', { arr }, false, cb);
							min_mci = parseInt(min_mci);
						}
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
```
