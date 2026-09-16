### Title
AA `timestamp` value is sender-selectable via `last_ball`/`last_ball_unit`, allowing bypass of time-locks, decay windows, and challenge periods in Autonomous Agents - (File: validation.js, formula/evaluation.js)

### Summary
In ocore, oscript formulas evaluated inside Autonomous Agents (AAs) expose a `timestamp` keyword that does **not** reflect the real wall-clock time at which the trigger unit was posted. Instead it is bound to `objValidationState.last_ball_timestamp`, which is simply the `timestamp` field of whatever `last_ball_unit` the *trigger unit's author* chose to reference [1](#0-0) . Because the only protocol constraint on this choice is that the referenced last-ball MCI must not retreat below what the sender's chosen parent units already imply [2](#0-1) , an unprivileged unit poster has wide latitude to pick an older, already-stable ball (by choosing older/shallower parent units) and thereby present an artificially "stale" value of `timestamp` to the AA that processes their trigger, independent of the actual real-time clock. This is the ocore analog of block-timestamp/time-griefing manipulation described in the referenced report: instead of stalling block production to shift a decaying price, an attacker here directly selects which "chain time" checkpoint is fed into the AA's time-based logic.

### Finding Description
1. `timestamp` in oscript is parsed to the AST node `['timestamp']` [3](#0-2) , and it is a keyword reserved specifically for AA/formula evaluation [4](#0-3) .
2. During evaluation, this keyword resolves through `objValidationState`, which is populated once per unit validation from the sender-supplied `last_ball` / `last_ball_unit` fields of the very unit that triggers the AA: `objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index; objValidationState.last_ball_timestamp = objLastBallUnitProps.timestamp;` [1](#0-0) .
3. `last_ball` and `last_ball_unit` are ordinary fields chosen by whoever composes the unit (this is standard DAG bookkeeping, not an oracle-fed or network-enforced "current time"). The only sanity check applied is that the chosen last-ball MCI cannot retreat relative to what the unit's own chosen parents already carry: `if (max_parent_last_ball_mci > objValidationState.last_ball_mci) return callback("last ball mci must not retreat, ...")` [2](#0-1) . There is no requirement that the sender pick the *freshest* available stable ball, nor any bound tying `last_ball_timestamp` to the real posting time (unlike the raw per-unit `timestamp` field, which is checked against `Date.now()` with only a 5-second future tolerance [5](#0-4)  — that check applies to the unit's own timestamp, not to the referenced last-ball's timestamp used inside AA formulas).
4. `validateAuthentifiers`/definition-level `timestamp` relational checks in `definition.js` operate on the exact same attacker-influenced `objValidationState.last_ball_timestamp` [6](#0-5) .
5. Because a sender can choose which parent units to build on (any set of valid, non-conflicting free/stable units, per `validateParents`/`parent_composer.js` logic), and because `max_parent_last_ball_mci` is simply the maximum last-ball MCI already recorded by those chosen parents [7](#0-6) , a sender can deliberately pick older parent units to keep `max_parent_last_ball_mci` low, and then attach an old, already-stable `last_ball` consistent with that low bound. This lets the sender present an arbitrarily "rewound" `timestamp` value to the AA, decoupled from how much real time has actually elapsed.
6. AA authors are explicitly encouraged (in the shipped oscript examples used as reference semantics for `timestamp`) to use `timestamp` for exactly the security-critical purposes this undermines: recording a challenge/dispute period start (`var['close_start_ts'] = timestamp;`) and gating finalization on elapsed real time (`timestamp > var['close_start_ts'] + $close_timeout`) [8](#0-7) , gating maturity/expiry dates (`timestamp < 1556668800`) [9](#0-8) , and gating ICO expiry (`timestamp > $expiry_ts`) [10](#0-9) . All of these constructs implicitly assume `timestamp` tracks real elapsed time; the validation logic does not guarantee that.

### Impact Explanation
Any AA that uses `timestamp` for a time-lock, challenge/dispute window, decay schedule, or expiry check can have that logic bypassed by a party who benefits from making the AA believe less (or more, depending on the guard's direction) real time has passed than actually has. Concretely:
- In a payment-channel-style AA that records `close_start_ts = timestamp` at the start of a dispute period and only allows the non-initiating party to force-close once `timestamp > close_start_ts + close_timeout`, a malicious channel party can submit the "start closing" trigger with a deliberately stale (old) `last_ball`, recording an artificially early `close_start_ts`. This shrinks the honest counterparty's real-world window to submit a fresher signed state before the channel becomes force-closeable, letting the attacker finalize the channel on a stale balance and steal funds from the counterparty — an unauthorized-spending/fund-loss outcome.
- In a Dutch-auction or vesting-style AA gated by `timestamp` thresholds, the same mechanism lets a poster manipulate which side of a time boundary their trigger falls on, independent of the real clock, enabling early or unauthorized state transitions (e.g., bypassing a maturity/expiry gate, or re-entering a window that should already be closed).

This maps to the report's core impact — a poster manipulating the effective "time" seen by decaying/threshold logic to gain value they should not be entitled to — translated into ocore's DAG/AA execution model as a fund-loss/spending-authorization bug rather than a discounted NFT mint.

### Likelihood Explanation
Exploitability requires only that a malicious party compose a custom (non-standard-wallet) unit with a deliberately chosen `last_ball_unit`/parent set, which is standard low-level unit-construction capability available to any address (the wallet composer normally always picks the freshest available last-ball, but nothing in validation enforces this — a custom composer bypassing the default wallet flow can pick an older one). It requires no witness collusion, no network-level DoS, and no privileged role — it is fully reachable from a single posted (trigger) unit, matching the required threat model. The main uncertainty is that the magnitude of exploitable "time rewind" is bounded by how much slack exists between the sender's chosen parents' `last_ball_mci` and the actual current tip of the DAG; in a very actively used DAG this slack could be small unit-to-unit, but a deliberately-crafted low-activity chain of parents can still produce a large gap in wall-clock time versus `last_ball_timestamp`.

### Recommendation
- Do not let `objValidationState.last_ball_timestamp` be treated as a trustworthy proxy for "current time" in oscript AA formulas without additional bounds. Consider bounding the allowed staleness of the referenced `last_ball` relative to the unit's own (network-checked) `timestamp` field (e.g., require `objUnit.timestamp - last_ball_timestamp <= max_allowed_staleness`), rejecting units whose declared last-ball is unreasonably old relative to their own posting time.
- Alternatively, document explicitly (and enforce via a lint/warning in AA validation, `aa_validation.js`) that `timestamp` is a DAG-checkpoint value that can lag/be chosen by the trigger sender, and encourage AA authors to design challenge/decay/expiry logic that is robust to a sender deliberately using an older-than-necessary `last_ball` (e.g., by cross-checking against `mci` progression enforced through parent-linkage rather than trusting `timestamp` alone for security-critical countdowns).
- For state-channel-style AAs specifically, consider requiring that the "start closing" trigger's `last_ball_mci` be within N of the current known network tip MCI, or otherwise anchor the dispute window to MCI progression (which is monotonic and harder to rewind) rather than to the sender-influenced timestamp of an arbitrarily old ball.

### Proof of Concept
1. Construct a custom (non-standard-wallet) unit `U1` that triggers a payment-channel-like AA's "start closing" case. Rather than referencing the freshest available stable last-ball (as a normal wallet composer would), choose parent units and a `last_ball_unit` corresponding to a ball that is, say, 10 minutes old in real time but still satisfies `max_parent_last_ball_mci <= last_ball_mci` per `validateParents` [2](#0-1) .
2. The AA's state-update logic executes `var['close_start_ts'] = timestamp;` using `objValidationState.last_ball_timestamp` from the old ball [1](#0-0) , recording a `close_start_ts` that is ~10 minutes earlier than the real posting time.
3. Wait only `close_timeout - 10min` of real wall-clock time (rather than the full `close_timeout`), then submit a "confirm closure" trigger; because `timestamp > close_start_ts + close_timeout` is evaluated against the newer trigger's own (potentially near-real-time) last-ball timestamp, the condition is satisfied prematurely, shrinking the honest counterparty's real dispute window by up to 10 minutes and enabling early, unauthorized finalization of the channel's balances.

### Citations

**File:** validation.js (L280-287)
```javascript
	if (objUnit.version !== constants.versionWithoutTimestamp) {
		if (!isPositiveInteger(objUnit.timestamp))
			return callbacks.ifUnitError("timestamp required in version " + objUnit.version);
		var current_ts = Math.round(Date.now() / 1000);
		var max_seconds_into_the_future_to_accept = conf.max_seconds_into_the_future_to_accept || 5;
		if (objUnit.timestamp > current_ts + max_seconds_into_the_future_to_accept)
			return callbacks.ifTransientError("timestamp is too far into the future");
	}
```

**File:** validation.js (L668-674)
```javascript
	function readMaxParentLastBallMci(handleResult){
		storage.readMaxLastBallMci(conn, objUnit.parent_units, function(max_parent_last_ball_mci) {
			if (max_parent_last_ball_mci > objValidationState.last_ball_mci)
				return callback("last ball mci must not retreat, parents: "+objUnit.parent_units.join(', '));
			handleResult(max_parent_last_ball_mci);
		});
	}
```

**File:** validation.js (L737-738)
```javascript
					objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index;
					objValidationState.last_ball_timestamp = objLastBallUnitProps.timestamp;
```

**File:** formula/grammars/oscript.ne (L54-54)
```text
					'timestamp', 'storage_size', 'mci', 'this_address', 'response_unit', 'mc_unit', 'params', 'previous_aa_responses',
```

**File:** formula/grammars/oscript.ne (L489-491)
```text
	| "storage_size"  {% function(d) {return addLocation(['storage_size'], d); }  %}
	| "mci"  {% function(d) {return addLocation(['mci'], d); }  %}
	| "timestamp"  {% function(d) {return addLocation(['timestamp'], d); }  %}
```

**File:** definition.js (L1036-1048)
```javascript
			case 'timestamp':
				var relation = args[0];
				var timestamp = args[1];
				switch(relation){
					case '>': return cb2(objValidationState.last_ball_timestamp > timestamp);
					case '>=': return cb2(objValidationState.last_ball_timestamp >= timestamp);
					case '<': return cb2(objValidationState.last_ball_timestamp < timestamp);
					case '<=': return cb2(objValidationState.last_ball_timestamp <= timestamp);
					case '=': return cb2(objValidationState.last_ball_timestamp === timestamp);
					case '!=': return cb2(objValidationState.last_ball_timestamp !== timestamp);
					default: throw Error('unknown relation in mci: '+relation);
				}
				break;
```

**File:** test/ojson.test.js (L1040-1067)
```javascript
							if: `{ trigger.data.blackswan AND !var['blackswan'] AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA']] < 25 AND timestamp < 1556668800 }`,
							messages: [{
								app: 'state',
								state: `{
						var['blackswan'] = 1;
						response['blackswan'] = 1;
					}`
							}]
						},
						// 1 GB is now 50 USD, 1 byte is 50e-9 = 5e-8 USD
						// 1 usd asset is always 2.5e-8 USD, 1 gb asset is 1 byte minus 2.5e-8 USD
						{ // pay bytes in exchange for the assets
							if: `{
					if (trigger.output[[asset!=base]].asset == 'none')
						return false;
					$gb_asset_amount = trigger.output[[asset=var['gb_asset']]];
					$usd_asset_amount = trigger.output[[asset=var['usd_asset']]];
					if ($gb_asset_amount < 1e4 AND $usd_asset_amount < 1e4)
						return false;
					if ($gb_asset_amount == $usd_asset_amount){ // helps in case the exchange rate is never posted
						$bytes = $gb_asset_amount;
						return true;
					}
					if (var['blackswan'])
						$bytes = $usd_asset_amount;
					else{
						if (timestamp < 1556668800)
							bounce('wait for maturity date');
```

**File:** test/ojson.test.js (L1156-1168)
```javascript
							var['close_initiated_by'] = $party;
							var['close_start_ts'] = timestamp;
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

**File:** test/ojson.test.js (L1963-1964)
```javascript
						{ // finish the ICO
							if: `{ trigger.data.finish AND (trigger.address == $control_address OR timestamp > $expiry_ts) }`,
```
