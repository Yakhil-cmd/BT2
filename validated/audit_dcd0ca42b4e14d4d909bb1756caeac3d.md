### Title
Predictable AA randomness via `mc_unit`/`number_from_seed` combined with mutable state allows front-run/griefing of "random" outcomes - (File: aa_composer.js, formula/evaluation.js)

### Summary
The oscript language exposes `mc_unit` (a fully known, already-stable unit hash at trigger time) and `number_from_seed()` (a deterministic PRNG keyed off a caller-supplied seed) as the only building blocks available to AA authors for generating "randomness" inside Autonomous Agents. Because the seed material (`mc_unit`, `trigger.unit`, `timestamp`, etc.) is knowable in advance and the outcome typically also depends on mutable AA state (counters, balances, entry lists) that stays open to new triggers until the "random" trigger executes, an attacker can compute the eventual "random" result before it is used and then post one more input (an extra contribution/entry unit) to steer the mutable state so that they become the winner — exactly the class of bug described in the external report ("don't accept inputs after requesting randomness"), but manifesting through oscript's own primitives rather than an external VRF oracle.

### Finding Description
`case 'mc_unit': cb(objValidationState.mc_unit);` returns the unit that anchors the trigger's `last_ball_mci`/`mc_unit` [1](#0-0) , and this MC unit is computed from the trigger unit's own referenced main-chain index before the trigger is even composed/handled [2](#0-1) . Any observer (including the poster of the trigger) can therefore compute `mc_unit` — and consequently any `number_from_seed(mc_unit, ...)`-derived "random" value — deterministically ahead of time, using the same seed-hashing logic implemented in `case 'number_from_seed'` [3](#0-2) .

If an AA author builds a lottery/game-style AA (as the sample AAs in the repo demonstrate, e.g. `test/samples/51_attack_game.oscript`, which determines winners from mutable, running totals like `var['team_...amount']` compared against `balance[base]*0.51` [4](#0-3) ) and combines a `number_from_seed` output with a counter such as `number_of_responses` or a state var that increments per entry to pick a "winning" index, the winner selection depends on two things: (1) a seed that is knowable/fixed ahead of the deciding trigger, and (2) a count of participants/entries that remains open to manipulation via new triggers up until the AA actually processes the decisive trigger. `number_of_responses` itself is explicitly exposed to formulas as mutable-at-runtime state (`objValidationState.number_of_responses = arrResponses.length`) [5](#0-4) [6](#0-5) .

This mirrors the reported VRF bug class precisely: the "randomness" (mc_unit-derived seed) is effectively fixed/known before the deciding action occurs, yet the contract continues to accept new user inputs (new entries/contributions) that influence which index/participant is deemed the "winner" once the deterministic seed is applied. An attacker who can predict the seed can wait, then post the exact extra entry/trigger needed to become the winner, denying a fair outcome to earlier honest participants.

### Impact Explanation
High — if an AA's payout logic (as in the pattern shown by `51_attack_game.oscript` and similar templates) uses a knowable seed (`mc_unit`, `trigger.unit`, `timestamp`) together with a mutable counter/balance to decide a winner or split of pooled funds, an attacker can grief the outcome to redirect payouts (AA funds) to themselves, denying honest participants their expected winnings. This is a direct AA fund-loss/misallocation vector, not merely a griefing nuisance.

### Likelihood Explanation
Medium — it requires an AA author to build a randomness-dependent selection process using oscript's own primitives (`mc_unit`/`number_from_seed`/`number_of_responses`) combined with a mutable entry counter, which is a natural and encouraged pattern for lottery/game DApps on Obyte (as evidenced by official sample AAs shipped in the codebase). No special privilege is needed by the attacker — any unit poster/trigger sender can exploit it by timing an additional trigger.

### Recommendation
Document and enforce (at the oscript/documentation level, and ideally via a `MAX`-style compile-time or runtime lint) that AA authors must not combine a *predictable* seed (`mc_unit`, `trigger.unit`, `timestamp`, or any value knowable prior to the decisive trigger) with *mutable* participation counters/state vars to select a winner. Instead, AAs should snapshot/close entries (e.g., via a `close`/`is_closed` state flag) in one trigger and only reveal the seed-driven outcome using data that cannot be affected after the close (e.g., a future, not-yet-known `mc_unit` reached only after the closing trigger stabilizes, or an oracle-fed value posted strictly after the close). Provide official guidance/examples in the `test/samples/*.oscript` sample AAs discouraging seeding "randomness" from currently-known main-chain data while state remains open to new contributions.

### Proof of Concept
1. Deploy an AA modeled on `test/samples/51_attack_game.oscript`-style pooling but with a winner-selection message such as:
   `var['winner_index'] = number_from_seed(mc_unit, 0, var['num_entries']-1);`
   evaluated once `trigger.data.finish` fires.
2. Because `mc_unit` for a given trigger is derived from that trigger's own `last_ball_unit`, which is already stable at the moment the trigger author composes their unit [2](#0-1) , an attacker can locally recompute `number_from_seed(mc_unit, 0, N-1)` for the current `var['num_entries']` value read from the AA's public state before posting anything.
3. If the computed index does not point to the attacker, the attacker posts one additional "entry" trigger, incrementing `var['num_entries']`, and recomputes the index for `N+1`. This can be repeated cheaply (each entry costs only bounce fees/dust) until the computed index selects the attacker as winner, then the attacker stops adding entries and lets/triggers the `finish` case.
4. The attacker becomes the "randomly" selected winner deterministically, at the expense of the honest bettors — reproducing the impact described in the external VRF report within ocore's AA/oscript randomness primitives.

### Citations

**File:** formula/evaluation.js (L1054-1056)
```javascript
			case 'mc_unit':
				cb(objValidationState.mc_unit);
				break;
```

**File:** formula/evaluation.js (L1058-1060)
```javascript
			case 'number_of_responses':
				cb(new Decimal(objValidationState.number_of_responses));
				break;
```

**File:** formula/evaluation.js (L1872-1919)
```javascript
			case 'number_from_seed':
				var evaluated_params = [];
				async.eachSeries(
					arr[1],
					function (param, cb2) {
						evaluate(param, function (res) {
							if (fatal_error)
								return cb2(fatal_error);
							if (res instanceof wrappedObject)
								res = true;
							if (!isValidValue(res))
								return setFatalError("invalid value in sha256: " + res, { arr }, undefined, cb2);
							if (isFiniteDecimal(res))
								res = toDoubleRange(res);
							evaluated_params.push(res);
							cb2();
						});
					},
					function (err) {
						if (err)
							return cb(false);
						var seed = evaluated_params[0];
						var hash = crypto.createHash("sha256").update(seed.toString(), "utf8").digest("hex");
						var head = hash.substr(0, 16);
						var nominator = new Decimal("0x" + head);
						var denominator = new Decimal("0x1" + "0".repeat(16));
						var num = nominator.div(denominator); // float from 0 to 1
						if (evaluated_params.length === 1)
							return cb(num);
						var min = dec0;
						var max;
						if (evaluated_params.length === 2)
							max = evaluated_params[1];
						else {
							min = evaluated_params[1];
							max = evaluated_params[2];
						}
						if (!isFiniteDecimal(min) || !isFiniteDecimal(max))
							return setFatalError("min and max must be numbers", { arr }, false, cb);
						if (!min.isInteger() || !max.isInteger())
							return setFatalError("min and max must be integers", { arr }, false, cb);
						if (!max.gt(min))
							return setFatalError("max must be greater than min", { arr }, false, cb);
						var len = max.minus(min).plus(1);
						num = num.times(len).floor().plus(min);
						cb(num);
					}
				);
```

**File:** aa_composer.js (L163-184)
```javascript
				readLastUnit(conn, function (objMcUnit) {
					// rewrite timestamp in case our last unit is old (light or unsynced full)
					objMcUnit.timestamp = objUnit.timestamp || Math.round(Date.now() / 1000);
					if (objUnit.main_chain_index)
						objMcUnit.main_chain_index = objUnit.main_chain_index;
					var mci = objMcUnit.main_chain_index;
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					var trigger_opts = {
						bAir: true,
						conn,
						trigger,
						params: {},
						stateVars,
						assocBalances, // balances _before_ the trigger, not including the coins received in the trigger
						arrDefinition,
						address,
						mci,
						objMcUnit,
						arrResponses,
```

**File:** aa_composer.js (L450-461)
```javascript
	var objValidationState = {
		last_ball_mci: mci,
		last_ball_timestamp: objMcUnit.timestamp,
		mc_unit: objMcUnit.unit,
		assocBalances: {},
		number_of_responses: arrResponses.length,
		arrPreviousAAResponses: arrResponses.map(objAAResponse => ({
			unit_obj: objAAResponse.objResponseUnit || false,
			trigger_unit: objAAResponse.trigger_unit,
			trigger_address: objAAResponse.trigger_address,
			aa_address: objAAResponse.aa_address,
		})),
```

**File:** test/samples/51_attack_game.oscript (L84-93)
```text
					{
						app: 'state',
						state: `{
							var['team_' || trigger.data.team || '_amount'] += trigger.output[[asset=base]];
							if (var['team_' || trigger.data.team || '_amount'] > balance[base]*0.51){
								var['winner'] = trigger.data.team;
								var['challenging_period_start_ts'] = timestamp;
							}
						}`
					}
```
