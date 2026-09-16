### Title
TPS-Fee Rate-Limiting Bypass via Concurrent Validation of Units from Different Authors - (File: validation.js)

### Summary
The TPS-fee mechanism is ocore's analog of a rate limiter: it charges an escalating fee (`min_acceptable_tps_fee`) based on the *current* count of pending (unstable) units, in order to throttle unit throughput and deter spam/flooding. This counter, `storage.getCurrentTps()`, is computed purely from the in-memory `storage.assocUnstableUnits` map [1](#0-0) , which is only updated by `writer.saveJoint` **after** a unit has passed validation and is committed [2](#0-1) . Because `validation.validate()` only takes a mutex lock scoped to the unit's *author addresses* (`mutex.lock(arrAuthorAddresses, …)`), not a global lock [3](#0-2) , units from different authors can be validated fully concurrently, all reading the same stale `assocUnstableUnits` snapshot and thus the same (too-low) `min_acceptable_tps_fee`, before any of them is added to the map. This lets an attacker controlling many addresses (or colluding accounts) flood the network with units concurrently at a fee level intended only for a low-load network, defeating the anti-spam rate limiter — directly analogous to the `express-brute` "concurrent requests cause the package to incorrectly count requests, allowing rate-limit bypass" bug class.

### Finding Description
`validateTpsFee()` computes `current_tps_fee = storage.getCurrentTpsFee(0, count_units)` and `min_acceptable_tps_fee = current_tps_fee * min_acceptable_tps_fee_multiplier * count_units` and rejects the unit (via `createTransientError`) only if `tps_fee < min_acceptable_tps_fee` [4](#0-3) .

`getCurrentTps()`/`getCurrentTpsFee()` derive the throughput estimate strictly from the process-local in-memory table `assocUnstableUnits`, iterating over units currently believed unstable, without touching the database inside a serialized transaction boundary shared across authors [5](#0-4) .

`assocUnstableUnits` is populated only in `writer.saveJoint`, which runs after `validation.validate()`'s `ifOk` callback fires and only for the unit that is actually being written [2](#0-1) .

The concurrency boundary for validation is `mutex.lock(arrAuthorAddresses, …)` in `validation.js`, keyed by the *posting unit's authors*, not a global "validation" key [3](#0-2) . This means N units from N different addresses submitted at nearly the same instant can all run `validateTpsFee` in parallel database transactions, all observing the same (pre-increment) `assocUnstableUnits` snapshot, and all compute the same low `min_acceptable_tps_fee`. Each of them independently satisfies the check, and only after each one's `writer.saveJoint` completes does the shared in-memory counter increase — too late to affect the units that already passed the check concurrently.

Note that `handleJoint` in `network.js` does hold a broader `assocUnitsInWork`/host-level lock during processing of a single joint, but this only prevents re-processing of the *same* unit hash; it places no serialization across different units/authors being validated and written simultaneously, so the race window described above is real at the multi-author level [6](#0-5) .

### Impact Explanation
This is a rate-limiting/anti-spam bypass, not a fund-theft bug: attackers who control (or rent) many independent addresses can burst-submit units in parallel, each computed against a stale, artificially low `current_tps_fee`, and thereby pay far less in TPS fees than the network's throttling design intends for that load level. This lets an attacker flood the DAG with cheap units beyond the intended rate, which can degrade network throughput/latency and unfairly shift TPS-fee economics, weakening the network's built-in flood/DoS mitigation for new-unit submission (an oscript/ojson-unrelated protocol safeguard reachable by any ordinary unit poster). It does not directly enable double-spend, inflation, or fund loss, so the impact is bounded to degraded rate-limiting guarantees and fee-based spam protection, matching a Medium-severity classification consistent with the source advisory.

### Likelihood Explanation
Exploitation requires an attacker to control multiple independent addresses (easy to generate) and to submit multiple units concurrently within the short window before each is separately committed and reflected in `assocUnstableUnits`. Given typical unit validation/write latencies (DB round-trips, main-chain updates, kvstore batch writes) span tens of milliseconds or more, and full nodes process units from unrelated authors concurrently by design (mutex is per-author, not global), this race window is realistically and repeatedly exploitable by a moderately resourced attacker running many parallel submissions, without needing to control any peer, hub, or network-level component — it only requires posting ordinary units as an unprivileged unit poster.

### Recommendation
Serialize or atomically account for the TPS-fee throughput counter so that concurrent validations across different authors cannot observe the same "current tps" snapshot. Options: (1) reserve/increment a pending-unit slot in `assocUnstableUnits` (or a dedicated in-flight counter) at the start of validation, before the TPS-fee check, and release it if validation later fails; (2) serialize the "compute current tps / accept tps_fee" step under a single global mutex key across all units, independent of author address, so admission decisions for the rate limiter itself are strictly ordered; (3) recompute/re-validate the TPS-fee condition again at commit time inside `writer.saveJoint` under a global lock as a final authoritative check, rejecting/reverting if the fee no longer meets the (now updated) threshold.

### Proof of Concept
1. Attacker controls addresses A1..An (independent, unrelated authors), each with sufficient balance to author a minimal unit.
2. Attacker crafts n units, one per address, each with `tps_fee` computed/signed against the currently-observed low `getCurrentTpsFee()` value (e.g., via `composer.estimateTpsFee`) at time T0, when `assocUnstableUnits` contains few pending units.
3. Attacker broadcasts all n units to the node at nearly the same time.
4. Because `mutex.lock(arrAuthorAddresses, …)` only serializes per-author, the node's `validation.validate()` for each of the n units runs concurrently (different DB connections/transactions), and each calls `validateTpsFee` → `storage.getCurrentTpsFee(0, count_units)`, which reads `assocUnstableUnits` before any of the n units have been added by `writer.saveJoint` [7](#0-6) [5](#0-4) .
5. All n units pass the `tps_fee < min_acceptable_tps_fee` check using the stale, low threshold, and are subsequently written via `writer.saveJoint`, each independently incrementing `assocUnstableUnits` only afterward [2](#0-1) .
6. Net effect: n units were admitted paying fees appropriate for a much lower observed load than the true instantaneous load (n units in flight), demonstrating a bypass of the intended TPS-fee rate-limiting/anti-flood mechanism.

(Note: full confirmation that no additional serialization exists elsewhere in the write pipeline that would close this window was not exhaustively verified beyond the `handleJoint`/`assocUnitsInWork` per-unit lock in `network.js`; a background Devin session with runtime/test access could add concurrency tests to empirically confirm the race timing.)

### Citations

**File:** storage.js (L1361-1402)
```javascript
function getCurrentTps(shift = 0, count_units = 1) {
	if (last_stable_mci === null)
		throw Error(`getCurrentTps: last_stable_mci not set yet`);
	const since_mci = last_stable_mci + shift;
	let count = count_units; // include the current unit and its AA responses
	let since_timestamp = 0;
	const now = Math.ceil(Date.now() / 1000);
	for (let unit in assocUnstableUnits) {
		const objUnitProps = assocUnstableUnits[unit];
		if (objUnitProps.timestamp > now) continue; // skip future-timestamped units
		if (objUnitProps.main_chain_index > since_mci || objUnitProps.main_chain_index === null)
			count += getCountUnitsPayingTpsFee(objUnitProps);
		else if (shift > 0 && objUnitProps.main_chain_index === since_mci) {
			if (objUnitProps.timestamp > since_timestamp)
				since_timestamp = objUnitProps.timestamp;
		}
	}
	if (count === count_units)
		return 0;
	//	throw Error(`getCurrentTps: no unstable units`);
	if (shift === 0) {
		const arrLastStableUnitProps = assocStableUnitsByMci[last_stable_mci];
		if (!arrLastStableUnitProps)
			throw Error(`getCurrentTps: no stable units at last stable mci ${last_stable_mci}`);
		for (let { timestamp } of arrLastStableUnitProps) {
			if (timestamp > since_timestamp)
				since_timestamp = timestamp;
		}
	}
	if (since_timestamp === 0)
		throw Error(`since_timestamp = 0, shift=${shift}, last_stable_mci=${last_stable_mci}`)
	const elapsed = (Math.round(Date.now() / 1000) - since_timestamp) || elapsedTimeWhenZero;
	console.log(`getCurrentTps shift=${shift}, date ${new Date()}, diff ${Math.round(Date.now() / 1000) - since_timestamp} ${count}/${elapsed}`);
	return count / elapsed;
}

function getCurrentTpsFee(shift = 0, count_units = 1) {
	const tps = getCurrentTps(shift, count_units);
	console.log(`current tps with shift ${shift} ${tps}`);
	const base_tps_fee = getSystemVar('base_tps_fee', last_stable_mci);
	const tps_interval = getSystemVar('tps_interval', last_stable_mci);
	return Math.round(base_tps_fee * (exp(tps / tps_interval) - 1));
```

**File:** writer.js (L590-598)
```javascript
			var batch = bCordova ? null : (bInLargerTx ? objValidationState.batch : kvstore.batch());
			if (bGenesis){
				storage.assocStableUnits[objUnit.unit] = objNewUnitProps;
				storage.assocStableUnitsByMci[0] = [objNewUnitProps];
				console.log('storage.assocStableUnitsByMci', storage.assocStableUnitsByMci)
			}
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
```

**File:** validation.js (L354-357)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** validation.js (L1050-1095)
```javascript
async function validateTpsFee(conn, objJoint, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || !objValidationState.last_ball_mci)
		return callback();
	const objUnit = objJoint.unit;
	if (objValidationState.bAA) {
		if ("tps_fee" in objUnit)
			return callback("tps_fee in AA response");
		return callback();
	}
	if ("content_hash" in objUnit) // tps_fee and other unit fields have been already stripped
		return callback();
	const objUnitProps = {
		unit: objUnit.unit,
		parent_units: objUnit.parent_units,
		best_parent_unit: objValidationState.best_parent_unit,
		last_ball_unit: objUnit.last_ball_unit,
		timestamp: objUnit.timestamp,
		count_primary_aa_triggers: objValidationState.count_primary_aa_triggers,
		max_aa_responses: objUnit.max_aa_responses,
	};
	const count_units = storage.getCountUnitsPayingTpsFee(objUnitProps);
	const min_tps_fee = await storage.getLocalTpsFee(conn, objUnitProps, count_units);
	console.log('validation', {min_tps_fee}, objUnitProps)
	
	// compare against the current tps fee or soft-reject
	const current_tps_fee = objJoint.ball ? 0 : storage.getCurrentTpsFee(0, count_units); // very low while catching up
	const min_acceptable_tps_fee_multiplier = objJoint.ball ? 0 : storage.getMinAcceptableTpsFeeMultiplier();
	const min_acceptable_tps_fee = current_tps_fee * min_acceptable_tps_fee_multiplier * count_units;

	const author_addresses = objUnit.authors.map(a => a.address);
	const bFromOP = isFromOP(author_addresses, objValidationState.last_ball_mci);
	const recipients = storage.getTpsFeeRecipients(objValidationState.last_ball_mci < constants.tpsFeeRecipientsFixMci ? objUnit.earned_headers_commission_recipients : storage.ehcr2assoc(objUnit.earned_headers_commission_recipients), author_addresses);
	for (let address in recipients) {
		const share = recipients[address] / 100;
		if (!share)
			throw Error(`invalid share for address ${address}: ${share}`);
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
		const tps_fee = tps_fees_balance / share + objUnit.tps_fee;
		if (tps_fee < min_acceptable_tps_fee) {
			if (!bFromOP)
				return callback(createTransientError(`tps fee on address ${address} must be at least ${min_acceptable_tps_fee}, found ${tps_fee}`));
			console.log(`unit from OP, hence accepting despite low tps fee on address ${address} which must be at least ${min_acceptable_tps_fee} but found ${tps_fee}`);
		}
```

**File:** network.js (L1258-1294)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
					if (objJoint.unsigned)
						throw Error("ifOk() unsigned");
					if (bPosted && objValidationState.sequence !== 'good') {
						validation_unlock();
						callbacks.ifUnitError("The transaction would be non-serial (a double spend)");
						delete assocUnitsInWork[unit];
						unlock();
						if (ws)
							writeEvent('nonserial', ws.host);
						return;
					}
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
						}
					}
					writer.saveJoint(objJoint, objValidationState, null, function(){
						validation_unlock();
						callbacks.ifOk();
						unlock();
						if (ws)
							writeEvent((objValidationState.sequence !== 'good') ? 'nonserial' : 'new_good', ws.host);
						notifyWatchers(objJoint, objValidationState.sequence === 'good', ws);
						if (objValidationState.arrUnitsGettingBadSequence)
							notifyWatchersAboutUnitsGettingBadSequence(objValidationState.arrUnitsGettingBadSequence);
						if (!bCatchingUp)
							eventBus.emit('new_joint', objJoint);
					});
```
