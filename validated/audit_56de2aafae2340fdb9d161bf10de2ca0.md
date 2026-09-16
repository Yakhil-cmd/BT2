This confirms `system_vote` for `base_tps_fee`/`tps_interval`/`tps_fee_multiplier` is castable by **any address** (not OP-only — `validateInlinePayload` only checks `!objValidationState.bAA`, no OP-only restriction), and votes are weighted by any voter's own on-chain balance and tallied by `countVotes()` in `main_chain.js`, taking the **median** value among distinct voted values. This is reachable by an unprivileged unit poster, matching the report's bug class (an economically critical numeric parameter lacking a bounded range check).

### Title
Unbounded `tps_fee_multiplier`/`base_tps_fee`/`tps_interval` system-vote values before range check was introduced - (File: `validation.js`)

### Summary
Analogous to the `_feePercentage` finding (an economic parameter without an enforced numeric range), `ocore`'s `system_vote` validation for the TPS-fee governance parameters (`base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) originally only checked that the value was a positive finite number, with no upper/lower bound, until a later fix gated behind `constants.pemCurvesFixMci`.

### Finding Description
In `validateInlinePayload()`'s `system_vote` case, votes for `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are validated with: [1](#0-0) 
Any address (any unit poster, no OP-only restriction) can send an `app: "system_vote"` message, as the only gating is `!objValidationState.bAA` and one-vote-per-unit: [2](#0-1) 

Votes are tallied later by `countVotes()` in `main_chain.js`, which computes the balance-weighted **median** of all distinct voted values and commits it as the new `system_vars` value used network-wide to compute TPS fees: [3](#0-2) 

Before `pemCurvesFixMci`, the extra bound checks (`tps_interval >= 0.1`, `base_tps_fee <= 1e8`, `tps_fee_multiplier` between 1 and 1000) did not exist — only `value > 0` and `isFinite` were enforced, so a coalition of addresses controlling a sufficient balance share could push the median to an extreme value (e.g., an astronomically large `tps_fee_multiplier` or `base_tps_fee`, or a `tps_interval` near zero), since the only requirement for a vote to count is meeting `constants.SYSTEM_VOTE_MIN_SHARE` of `TOTAL_WHITEBYTES` participating over an expanding time window: [4](#0-3) 

### Impact Explanation
`tps_fee_multiplier`, `base_tps_fee`, and `tps_interval` directly determine the mandatory `tps_fee` every unit must pay, computed via `getLocalTpsFee`/`getCurrentTpsFeeToPay`: [5](#0-4) . If these unbounded values were driven to extremes, the network could become effectively unable to confirm new units (fees priced out of reach for ordinary senders) or, at the other extreme, fees could be forced toward degenerate values that undermine the anti-spam mechanism, both of which fall under "network unable to confirm new units" / consensus-affecting outcomes.

### Likelihood Explanation
Exploitation requires assembling `SYSTEM_VOTE_MIN_SHARE` of `TOTAL_WHITEBYTES` in balance-weighted votes for extreme values, which is a real but non-trivial economic bar; it is not an OP-only privileged path since any address's balance counts toward the vote, distinguishing it from the (excluded) "operator-only" category. The vulnerable code path (values <=0 rejected, but no upper bound) is confirmed to have existed prior to `pemCurvesFixMci`, matching the report's pattern of "unregulated percentage/parameter fixed later with an explicit range check."

### Recommendation
Confirm the range checks introduced at `pemCurvesFixMci` (`validation.js:1898-1904`) are unconditionally enforced (not gated behind an MCI flag going forward) for all `system_vote` numeric subjects, and ensure any newly introduced governance-voted numeric parameters get explicit min/max bounds validated at the same point the value is first accepted into `system_votes`, rather than relying on a later hard-fork-style fix.

### Proof of Concept
1. Prior to `pemCurvesFixMci`, craft units from multiple addresses (that collectively hold ≥ `SYSTEM_VOTE_MIN_SHARE` of `TOTAL_WHITEBYTES`) each containing `{app: "system_vote", payload: {subject: "tps_fee_multiplier", value: 1e15}}` and one `system_vote_count` message referencing `"tps_fee_multiplier"`.
2. Post them and let them stabilize; `countVotes()` computes the balance-weighted median, which — lacking an upper bound at that MCI — accepts `1e15` as the new `tps_fee_multiplier` in `system_vars`.
3. All subsequent `tps_fee` calculations via `getCurrentTpsFeeToPay`/`getLocalTpsFee` scale by this multiplier, pricing ordinary transactions out of the network.

### Citations

**File:** validation.js (L1844-1860)
```javascript
		case "system_vote":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot vote for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot cast system vote");
			if (objValidationState.bHasSystemVote)
				return callback("can be only one system vote");
			objValidationState.bHasSystemVote = true;
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["subject", "value"]))
				return callback("unknown fields in " + objMessage.app);
			if (typeof payload.subject !== "string")
				return callback("subject must be string");
			if (!payload.value)
				return callback("no value in " + objMessage.app);
			switch (payload.subject) {
```

**File:** validation.js (L1893-1905)
```javascript
				case "base_tps_fee":
				case "tps_interval":
				case "tps_fee_multiplier":
					if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
						return callback(payload.subject + " must be a positive number");
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) {
						if (payload.subject === "tps_interval" && payload.value < 0.1)
							return callback(payload.subject + " must be at least 0.1");
						if (payload.subject === "base_tps_fee" && payload.value > 1e8)
							return callback(payload.subject + " must be at most 1e8");
						if (payload.subject === "tps_fee_multiplier" && (payload.value < 1 || payload.value > 1000))
							return callback(payload.subject + " must be between 1 and 1000");
					}
```

**File:** main_chain.js (L1807-1821)
```javascript
	// Vote timeframe. If too small share has voted in the previous year, expand the period to 2 years. If still small, expand to 3 years, and so on.
	let since_timestamp = mc_timestamp;
	while (true) {
		since_timestamp -= 365 * 24 * 3600;
		if (since_timestamp <= activation_timestamp)
			break;
		const [{ total_balance }] = await conn.query(`SELECT SUM(balance) AS total_balance 
			FROM voter_balances
			WHERE address IN (
				SELECT DISTINCT address FROM system_votes WHERE subject=? AND timestamp>=?
			)`,
			[subject, since_timestamp]);
		if (total_balance >= constants.SYSTEM_VOTE_MIN_SHARE * constants.TOTAL_WHITEBYTES)
			break;
	}
```

**File:** main_chain.js (L1878-1903)
```javascript
		case "threshold_size":
		case "base_tps_fee":
		case "tps_interval":
		case "tps_fee_multiplier":
			const rows = await conn.query(`SELECT value, SUM(balance) AS total_balance
				FROM numerical_votes
				CROSS JOIN voter_balances USING(address)
				WHERE timestamp>=? AND subject=?
				GROUP BY value
				ORDER BY value`,
				[since_timestamp, subject]
			);
			console.log(`total votes for`, subject, rows);
			const total_voted_balance = rows.reduce((acc, row) => acc + row.total_balance, 0);
			let accumulated = 0;
			for (let { value: v, total_balance } of rows) {
				accumulated += total_balance;
				if (accumulated >= total_voted_balance / 2) {
					value = v;
					break;
				}
			}
			if (value === undefined)
				throw Error(`no median value for ` + subject);
			storage.systemVars[subject].unshift({ vote_count_mci: mci, value, is_emergency });
			break;
```

**File:** storage.js (L1339-1408)
```javascript
async function getLocalTpsFee(conn, objUnitProps, count_units = 1) {
	const objLastBallUnitProps = await readUnitProps(conn, objUnitProps.last_ball_unit);
	const last_ball_mci = objLastBallUnitProps.main_chain_index;
	const base_tps_fee = getSystemVar('base_tps_fee', last_ball_mci); // unit's mci is not known yet
	const tps_interval = getSystemVar('tps_interval', last_ball_mci);
	const tps_fee_multiplier = getSystemVar('tps_fee_multiplier', last_ball_mci);
	const tps = await getLocalTps(conn, objUnitProps, count_units);
	console.log(`local tps at ${objUnitProps.unit} ${tps}`);
	const tps_fee_per_unit = Math.round(tps_fee_multiplier * base_tps_fee * (exp(tps / tps_interval) - 1));
	return count_units * tps_fee_per_unit;
}

function getCountUnitsPayingTpsFee(objUnitProps) {
	let count_units = 1;
	if (objUnitProps.count_primary_aa_triggers) {
		const max_aa_responses = (typeof objUnitProps.max_aa_responses === "number") ? objUnitProps.max_aa_responses : constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER;
		count_units += objUnitProps.count_primary_aa_triggers * max_aa_responses;
	}
	return count_units;
}

// current tps based on units with mci greater than last_stable_mci + shift
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
}

function getCurrentTpsFeeToPay(shift = 0, count_units = 1) {
	const tps_fee_multiplier = getSystemVar('tps_fee_multiplier', last_stable_mci);
	return Math.round(tps_fee_multiplier * getCurrentTpsFee(shift, count_units));
}
```
