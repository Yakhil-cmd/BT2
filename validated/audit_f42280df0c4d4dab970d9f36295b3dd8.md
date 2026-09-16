### Title
Retroactive TPS-fee recomputation using post-vote system parameters can drive an address's `tps_fees_balance` permanently negative, freezing that address's ability to post units - (File: `storage.js`, `validation.js`, `main_chain.js`)

### Summary
`base_tps_fee`, `tps_interval` and `tps_fee_multiplier` are community-votable system parameters (`system_vote` / `system_vote_count` messages, tallied in `countVotes()`), just like the auditable `PRICE_PER_PLOT` config value in the Munchables report. When such a parameter changes, the fee that a unit is *retroactively judged to owe* (computed at stabilization time using the parameter value applicable at the unit's own `mci`) can diverge sharply from the fee that was actually *approved when the unit was validated* (computed against the still-current parameter at `last_ball_mci`, before the new vote took effect). This divergence is booked as a persistent per-address debit in `tps_fees_balance`, and future units from that address are rejected until the (unbounded) debt is repaid — a config-driven freeze mechanism structurally analogous to the LandManager underflow.

### Finding Description
Every unit pays a flat `tps_fee` chosen by its author and validated in `validateTpsFee()`: [1](#0-0) 

`min_tps_fee` here is computed from `storage.getLocalTpsFee()`, which reads `base_tps_fee`/`tps_interval` at `last_ball_mci` — i.e. the system-variable value in force *at the moment the unit is composed and validated*: [2](#0-1) 

Later, once the unit's own `mci` actually stabilizes, `updateTpsFees()` recomputes the fee the unit is deemed to owe via `getFinalTpsFee()`, but this time it reads the system variable *at the unit's own `mci`* using `getSystemVar()`: [3](#0-2) 

`getSystemVar()` looks up whichever `system_vars` row has the largest `vote_count_mci < mci`: [4](#0-3) 

If a `system_vote_count` for `base_tps_fee`/`tps_interval`/`tps_fee_multiplier` is processed with a `vote_count_mci` that falls between the unit's `last_ball_mci` (used at validation time) and the unit's own `mci` (used at settlement time), then `getFinalTpsFee()` at settlement uses a *different, possibly much larger*, parameter value than the one `validateTpsFee()` used to approve the unit's `tps_fee`. The delta is booked unconditionally: [5](#0-4) 

`countVotes()` performs exactly this kind of parameter update, driven purely by weighted community votes with no coupling to already-in-flight units' assumed fees: [6](#0-5) 

Crucially, once `tps_fees_balance` for an address becomes deeply negative, every subsequent unit from that address must satisfy `tps_fees_balance + objUnit.tps_fee*share >= min_tps_fee*share` in `validateTpsFee()`, but a normal `tps_fee` computed by the composer only reflects *current* network load, not any backlog: [7](#0-6) 

There is no mechanism that lets a single new unit pay off the accumulated negative balance in one shot in an amount the composer is aware of; `composer.js`/`getCurrentTpsFeeToPay()` compute the fee for the new unit only from present-day tps, so the address can be permanently locked out of posting further payment units once the balance is sufficiently negative — precisely the "stale-parameter, mismatched-timeframe" pattern that caused the Munchables `_farmPlots` freeze, except here the mismatch is between the timeframe a fee is *approved* under and the timeframe it is *retroactively billed* under.

### Impact Explanation
This can permanently prevent an honest address (or, at network scale, many addresses that happened to have units near a system-variable vote boundary) from getting further base-asset units accepted, i.e. their bytes become effectively unspendable through normal composition — a freeze-of-funds condition matching the "AA fund loss or freezing" / "network unable to confirm new units" impact classes. Because `countVotes()` and `updateTpsFees()` are part of the deterministic main-chain stabilization pipeline executed by every full node, all nodes would agree on the same (incorrect) negative balance, so this is a consensus-safe but functionally crippling DoS rather than a fork.

### Likelihood Explanation
`system_vote`/`system_vote_count` are posted by ordinary addresses with weighted vote balances (Order Providers vote on the actual value, but the vote-count mechanism itself is triggered by any `system_vote_count` message), and votes on `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are a documented, expected, periodically-used feature (not an edge case). Any transaction burst that straddles a parameter change (which happens naturally whenever the network votes to change fee parameters, e.g. in response to load) can trigger the mismatch, making this reachable without any privileged access — a normal user simply composing and posting units around the time of a routine fee-parameter vote.

### Recommendation
Do not retroactively bill a unit using the system-variable value in force at its own `mci`; instead, `getFinalTpsFee()` should use the same value that `validateTpsFee()` used at approval time (i.e., derived from `last_ball_mci`/the value visible to the composer), or alternatively cap/clamp `total_tps_fees_delta` so that a parameter vote cannot retroactively create debt beyond what the unit could have anticipated when it was composed and validated. Additionally, `validateTpsFee()` should allow a unit to explicitly declare and pay down existing negative `tps_fees_balance` so an address is never left in an unrecoverable state.

### Proof of Concept
1. Address `A` posts unit `U` with a `tps_fee` sized to satisfy `min_tps_fee` computed from `base_tps_fee`/`tps_interval` in force at `U`'s `last_ball_mci` (validated per `validation.js:1050-1098`).
2. Before `U`'s own `mci` stabilizes, the network processes a `system_vote_count` for `base_tps_fee` (or `tps_interval`) via `countVotes()` (`main_chain.js:1878-1903`) with a `vote_count_mci` landing between `U`'s `last_ball_mci` and `U`'s `mci`, substantially raising the effective fee requirement.
3. When `U` stabilizes, `updateTpsFees()` calls `getFinalTpsFee(U)` (`storage.js:1238-1245`), which now reads the *new, higher* `base_tps_fee`/`tps_interval` for `U`'s `mci`, producing `tps_fee` much larger than `U.tps_fee` that was actually paid.
4. `total_tps_fees_delta = U.tps_fee - tps_fee` is strongly negative and is added into `tps_fees_balances` for address `A` (`storage.js:1259-1271`).
5. Every subsequent unit authored by `A` is checked in `validateTpsFee()` against this now deeply negative `tps_fees_balance` (`validation.js:1086-1089`); since a normally-composed `tps_fee` only reflects present-day network load and not the backlog, the check keeps failing, and address `A` can no longer get base-asset units accepted — its funds are effectively frozen.

### Citations

**File:** validation.js (L1084-1096)
```javascript
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
	}
```

**File:** storage.js (L1132-1137)
```javascript
function getSystemVar(subject, mci) {
	for (let { vote_count_mci, value } of systemVars[subject])
		if (mci > vote_count_mci)
			return value;
	throw Error(subject + ` not found for mci ` + mci);
}
```

**File:** storage.js (L1238-1245)
```javascript
function getFinalTpsFee(objUnitProps) {
	const mci = objUnitProps.main_chain_index;
	const base_tps_fee = getSystemVar('base_tps_fee', mci); // not at last_ball_mci
	const tps_interval = getSystemVar('tps_interval', mci);
	const tps = getFinalTps(objUnitProps);
	console.log(`final tps at ${objUnitProps.unit} ${tps}`);
	return Math.round(base_tps_fee * (exp(tps / tps_interval) - 1));
}
```

**File:** storage.js (L1247-1272)
```javascript
async function updateTpsFees(conn, arrMcis) {
	console.log('updateTpsFees', arrMcis);
	for (let mci of arrMcis) {
		if (mci < constants.v4UpgradeMci) // not last_ball_mci
			continue;
		for (let objUnitProps of assocStableUnitsByMci[mci]) {
			if (objUnitProps.bAA)
				continue;
			if (objUnitProps.sequence !== 'good' && mci >= constants.pemCurvesFixMci)
				continue;
			const tps_fee = getFinalTpsFee(objUnitProps) * (1 + (objUnitProps.count_aa_responses || 0));
			await conn.query("UPDATE units SET actual_tps_fee=? WHERE unit=?", [tps_fee, objUnitProps.unit]);
			const total_tps_fees_delta = (objUnitProps.tps_fee || 0) - tps_fee; // can be negative
			//	if (total_tps_fees_delta === 0)
			//		continue;
			/*	const recipients = (objUnitProps.assocEarnedHeadersCommissionRecipients && total_tps_fees_delta < 0)
					? storage.getTpsFeeRecipients(objUnitProps.assocEarnedHeadersCommissionRecipients, objUnitProps.author_addresses)
					: (objUnitProps.assocEarnedHeadersCommissionRecipients || { [objUnitProps.author_addresses[0]]: 100 });*/
			const recipients = getTpsFeeRecipients(objUnitProps.assocEarnedHeadersCommissionRecipients, objUnitProps.author_addresses);
			for (let address in recipients) {
				const share = recipients[address];
				const tps_fees_delta = Math.floor(total_tps_fees_delta * share / 100);
				const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, mci]);
				const tps_fees_balance = row ? row.tps_fees_balance : 0;
				await conn.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", [address, mci, tps_fees_balance + tps_fees_delta]);
			}
```

**File:** storage.js (L1339-1349)
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
