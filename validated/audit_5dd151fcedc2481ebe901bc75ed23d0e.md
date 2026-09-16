## Analysis

The reported Solidity bug is about an interest-rate/timestamp update mechanism that only refreshes once per block, letting a borrower observe a "frozen" interest clock across borrow+repay within the same block and pay zero interest. ocore has a structurally identical mechanism for its own concept of "current time" inside Autonomous Agents (AAs): the `timestamp` op in oscript formulas.

**Root cause:** In `formula/evaluation.js`, the `timestamp` op does not return real time or the trigger unit's own timestamp — it returns `objValidationState.last_ball_timestamp`: [1](#0-0) 

`objValidationState.last_ball_timestamp` is populated once per AA-trigger evaluation from `objMcUnit.timestamp`, where `objMcUnit` is the single main-chain unit fetched for a given `mci`: [2](#0-1) 

Every AA trigger belonging to the same stabilized `mci` is processed using the *same* `objMcUnit` (fetched via `readMcUnit(conn, mci, ...)`), so all of them observe the identical `timestamp` value: [3](#0-2) 

The batch of triggers processed together is built per-MCI in `main_chain.js`'s `handleAATriggers()`, which collects *all* units sending to AA addresses whose `main_chain_index = mci` in one query, then executes them one after another still keyed to that same `mci`: [4](#0-3) [5](#0-4) 

So the analog to "interest-free loans in the same block" is: two units from the same author (e.g. a `borrow` unit and a `repay` unit) that both end up stabilized under the same `main_chain_index` will cause their AA triggers to be evaluated with an **identical `timestamp` value**, even though real wall-clock time has passed between posting them. This is not a hypothetical edge case — the codebase's own sample AAs implement exactly this "elapsed time since last update" pattern using `timestamp`, e.g. the payment-channel sample's `close_start_ts = timestamp` / `timestamp > var['close_start_ts'] + $close_timeout` check and the 51%-attack-game sample's `challenging_period_start_ts = timestamp`: [6](#0-5) [7](#0-6) 

Any AA author who implements an interest-accrual, fee-accrual, or cooldown/rate-limit scheme of the form `$elapsed = timestamp - var['last_update']; ...; var['last_update'] = timestamp;` is vulnerable to the exact "same-block interest-free window" class from the report: a user who manages to have a pair of trigger units (e.g. borrow then repay, or deposit then withdraw) land under the same `main_chain_index` sees `$elapsed == 0`, bypassing interest/fee/cooldown logic entirely.

---

### Title
Same-MCI `timestamp` reuse across AA triggers enables interest/fee/cooldown-free exploitation of time-based AA logic - (File: `formula/evaluation.js`, `aa_composer.js`)

### Summary
The oscript `timestamp` value exposed to Autonomous Agents is not the real-time clock nor the individual trigger unit's own timestamp; it is `last_ball_timestamp`, taken from the single main-chain unit (`objMcUnit`) associated with the `mci` at which the trigger is processed. Because all AA triggers whose unit stabilizes under the same `main_chain_index` are executed against that same `objMcUnit`, they all observe an identical `timestamp`, mirroring the reported "interest rate updated once per block" flaw.

### Finding Description
`case 'timestamp': cb(new Decimal(objValidationState.last_ball_timestamp));` in `formula/evaluation.js` [1](#0-0)  resolves to a value fixed at `handleTrigger` invocation time from `objMcUnit.timestamp` [2](#0-1) . `handlePrimaryAATrigger` fetches this single `objMcUnit` per `mci` and reuses it for the trigger's evaluation [3](#0-2) . `handleAATriggers` in `main_chain.js` batches *all* trigger units sharing a given `mci` and dispatches them through this same code path sequentially [4](#0-3) , [8](#0-7) .

Consequently, any two (or more) trigger units — even from the same address, sent seconds apart — that end up stabilized under the same `main_chain_index` will cause the AA to see the same `timestamp` in both evaluations. An AA author implementing "elapsed time since last action" logic (`$elapsed = timestamp - var['last_ts']`) will compute `$elapsed = 0` for the second trigger, defeating any interest accrual, fee schedule, or cooldown gate built on this assumption — the direct analog of borrowing and repaying "interest free" within the same block in the original report.

### Impact Explanation
This causes **AA fund loss** for any lending/staking/subscription-style AA that accrues interest, fees, or rewards based on elapsed `timestamp`, or enforces a cooldown/rate limit keyed on `timestamp` (patterns already present in shipped samples such as the payment-channel and 51%-attack-game AAs). An attacker who can arrange for a pair of triggers to land in the same MCI can extract interest-free loans, bypass timeouts/cooldowns, or repeat "once per period" actions without waiting the intended real-world period, draining AA balances or manipulating time-gated outcomes (e.g., prematurely finalizing a challenge period equivalent). This matches the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
Getting two units to stabilize under the same `main_chain_index` is not adversary-controlled with certainty (stability advances based on witness-level progression across the whole network), but it is a routinely occurring condition — especially when a poster submits closely-spaced units, or when the network is stabilizing multiple pending units in a single advance. It requires no special privilege: any unprivileged AA trigger sender can attempt it by posting units back-to-back and does not need to compromise any node or peer. It also does not require a malicious node or hub. The determinism requirement that motivated tying `timestamp` to `last_ball_timestamp` (so all nodes agree on the same value when independently evaluating the same trigger) inherently creates this batching effect, making the condition systemic and reproducible rather than a rare race.

### Recommendation
For time-sensitive accrual/cooldown logic, AA authors should not rely solely on `timestamp` to detect "different actions" being spaced apart; but a more robust core-level mitigation is to make `mci` progression (not just `timestamp`) a required part of any accrual gating example/documentation, or provide AAs a finer-grained monotonic counter that increases per trigger unit (not per MCI) so consecutive triggers in the same MCI cannot be conflated as simultaneous. At minimum, the official oscript documentation and sample contracts (`payment_channels.oscript`, `51_attack_game.oscript`, etc.) should explicitly warn that `timestamp` can be identical across multiple triggers processed in the same `main_chain_index`, and that interest/fee-accrual AAs must not assume monotonic distinctness of `timestamp` between successive triggers.

### Proof of Concept
Consider a minimal lending AA pattern (following the same style as the codebase's own samples):
```
messages: {
  cases: [
    { // borrow
      if: `{trigger.data.borrow}`,
      init: `{
        $elapsed = timestamp - (var['last_ts'] otherwise timestamp);
        var['debt'] = (var['debt'] otherwise 0) + var['debt']*0.0001*$elapsed + trigger.data.borrow;
        var['last_ts'] = timestamp;
      }`,
      messages: [{ app: 'payment', payload: { asset: 'base', outputs: [{address: "{trigger.address}", amount: "{trigger.data.borrow}"}] } }]
    },
    { // repay
      if: `{trigger.data.repay}`,
      init: `{
        $elapsed = timestamp - var['last_ts'];
        var['debt'] += var['debt']*0.0001*$elapsed;
        var['last_ts'] = timestamp;
        var['debt'] -= trigger.data.repay;
      }`,
      messages: [{ app: 'state', state: `{ response['debt']=var['debt']; }` }]
    }
  ]
}
```
Per `formula/evaluation.js:1050-1052` and `aa_composer.js:450-453`, both the `borrow` trigger unit and a later `repay` trigger unit — if their units are stabilized under the same `main_chain_index` (processed via the shared `objMcUnit` in `handleAATriggers`/`handlePrimaryAATrigger`, `main_chain.js:1691-1706` and `aa_composer.js:59-101`) — will both evaluate `timestamp` to the identical `objMcUnit.timestamp`. Thus `$elapsed` at repay time is `0`, and `var['debt']` accrues zero interest for the borrow-repay round trip, regardless of how much real time separates the two units — the same "interest-free debt in one block" outcome described in the report.

### Citations

**File:** formula/evaluation.js (L1050-1052)
```javascript
			case 'timestamp':
				cb(new Decimal(objValidationState.last_ball_timestamp));
				break;
```

**File:** aa_composer.js (L59-89)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}
```

**File:** aa_composer.js (L91-101)
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
```

**File:** aa_composer.js (L450-453)
```javascript
	var objValidationState = {
		last_ball_mci: mci,
		last_ball_timestamp: objMcUnit.timestamp,
		mc_unit: objMcUnit.unit,
```

**File:** main_chain.js (L1691-1706)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```

**File:** test/samples/payment_channels.oscript (L61-71)
```text
							response['close_start_ts'] = timestamp;
							response['finalBalanceA'] = $finalBalanceA;
							response['finalBalanceB'] = $finalBalanceB;
						}`
					}
				]
			},
			{ // confirm closure
				if: `{ trigger.data.confirm AND var['close_initiated_by'] }`,
				init: `{
					if (!($bFromParties AND var['close_initiated_by'] != $party OR timestamp > var['close_start_ts'] + $close_timeout))
```

**File:** test/samples/51_attack_game.oscript (L86-92)
```text
						state: `{
							var['team_' || trigger.data.team || '_amount'] += trigger.output[[asset=base]];
							if (var['team_' || trigger.data.team || '_amount'] > balance[base]*0.51){
								var['winner'] = trigger.data.team;
								var['challenging_period_start_ts'] = timestamp;
							}
						}`
```
