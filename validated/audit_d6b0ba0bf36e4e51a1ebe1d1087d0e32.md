### Title
`timestamp` in oscript/AA formulas is derived from an attacker-chosen `last_ball`, not real current time, making time-based deadlines unreliable - (File: `validation.js`, `formula/evaluation.js`)

### Summary
The reported Uniswap issue is that a swap's `deadline` is set to `block.timestamp`, so it always equals "now" at inclusion time and gives zero real protection against delayed/held transactions. The analogous pattern in ocore is the `timestamp` keyword available to oscript/AA formulas: it does not reflect the actual wall-clock time the unit is processed, but is copied from `objValidationState.last_ball_timestamp`, i.e. the timestamp of whatever `last_ball_unit` the unit's author chose to reference. [1](#0-0) [2](#0-1) 

### Finding Description
Every AA in ocore that implements a "deadline"/"expiry"/"challenge period" check (`timestamp > $expiry_ts`, `timestamp < var['close_start_ts'] + $close_timeout`, "wait for maturity date", etc.) relies on the `timestamp` op, which evaluates to `objValidationState.last_ball_timestamp`: [3](#0-2) 

`last_ball_timestamp` is set from the `last_ball_unit` field of the *triggering unit itself* during validation, taken directly from the DB row for whatever ball the unit references: [4](#0-3) 

The only constraint enforced is that `last_ball_mci` must not be lower than `max_parent_limci` (the latest MC index already included via the unit's parents): [5](#0-4) 

There is no requirement that the referenced `last_ball` be the *most recent* stable ball available at broadcast time. The normal composer always picks the freshest stable ball (`pickParentUnitsAndLastBall` → `findLastStableMcBall`, `ORDER BY main_chain_index DESC LIMIT 1`), but this is a policy choice of the reference composer, not a protocol-enforced rule. A unit author who crafts (or uses a modified/light) composer can legally reference an older, still-valid, still-stable `last_ball_unit` as long as it satisfies the `limci` constraint, causing `timestamp` in their unit's AA trigger evaluation to reflect a much earlier point in time than the actual moment the unit is broadcast/processed.

This is directly analogous to the reported bug: just as `block.timestamp` passed as `deadline` always trivially satisfies the deadline check because it equals the time of execution (giving no real protection), `timestamp` in ocore formulas is *not* "now" but a value chosen, within limits, by whoever composes the triggering unit — the equivalent of the "the sender decides when to submit, and can pick a favorable timestamp."

### Impact Explanation
AA authors write time-gated logic assuming `timestamp` approximates real time:
- ICO/milestone contracts: `trigger.data.finish AND (trigger.address == $control_address OR timestamp > $expiry_ts)` [6](#0-5) 
- Payment-channel confirm/close: `timestamp > var['close_start_ts'] + $close_timeout` used to decide when the counter-party can force-close and claim last-known balances [7](#0-6) 
- Futures/option contracts gating maturity/blackswan logic on `timestamp < 1556668800` [8](#0-7) 

Because the trigger unit's author (an unprivileged party who can post any unit) controls which `last_ball_unit` to reference, they can bias `timestamp` backward (still-valid but stale ball) or, once real time has caught up, ensure `timestamp` is favorably positioned relative to deadlines they need to pass or avoid. In payment-channel-style AAs this can let a party who initiated closure with stale/lower balances prevent the peer from "too early" force-closing, or conversely claim a challenge/timeout has passed when in real wall-clock terms it has not, letting them extract funds (`$finalBalanceA`/`$finalBalanceB` payouts) before the honest timeout, or block the fraud-proof window. In auction/ICO-style AAs it can let a controller-independent caller finish an ICO earlier or later than the honest deadline intends, affecting refund vs. milestone-release logic and fund distribution. This maps to concrete fund-loss/freezing risk in AAs that rely on `timestamp` for time-locked payouts.

### Likelihood Explanation
Any unit author (an ordinary user posting a payment or an AA trigger) fully controls `last_ball`/`last_ball_unit` subject only to the `limci` monotonicity constraint enforced in `validation.js`; no witness/oracle/administrator cooperation is required. The manipulation window is bounded by how "behind" a still-valid stable ball can be relative to the true current MC tip, which can be non-trivial in periods of network activity or if the composer deliberately picks an older stable ball rather than the tip. Exploitability is highest for AAs that use tight, security-critical time windows (payment channel `close_timeout`, fraud-proof windows) rather than long ICO deadlines, since a modest bias is enough to flip a boundary condition.

### Recommendation
- Document explicitly (and warn AA authors) that `timestamp` is the timestamp of the referenced `last_ball`, not real time, and can lag/be chosen by the unit's author within the bounds of the `limci` constraint.
- For AAs where "current time" security-critical semantics are required, consider protocol changes such as bounding how far behind the current stable MC frontier a `last_ball` may lag before a unit is accepted, or providing a formula op that also exposes/enforces a minimum freshness of `last_ball_mci`/`last_ball_timestamp` relative to the node's currently known stable tip.
- For existing sample/production AAs (payment channels, ICO milestones, futures/option contracts) that gate fund movement on `timestamp` comparisons, recommend combining the check with `mci` freshness assertions or off-chain freshness attestations rather than relying solely on `timestamp`.

### Proof of Concept
1. An attacker/party in a payment-channel AA (`test/samples/payment_channels.oscript`) wants to force-close the channel using a *stale* balance state before the honest `close_timeout` truly elapses in wall-clock time, or wants to delay a `fraud_proof`/`confirm` transition.
2. Instead of using the reference wallet's composer (which always picks the freshest stable ball via `findLastStableMcBall`), the attacker crafts a unit whose `last_ball`/`last_ball_unit` reference an older-but-still-stable ball that satisfies only the minimal `max_parent_limci` requirement in `validateParents` (`validation.js:740-741`).
3. During validation, `objValidationState.last_ball_timestamp` is set to that older ball's timestamp (`validation.js:738`).
4. When the AA formula evaluates `timestamp` (`formula/evaluation.js:1050-1052`), it returns this older, attacker-influenced timestamp rather than real current time.
5. Time-gated conditions such as `timestamp > var['close_start_ts'] + $close_timeout` (`test/samples/payment_channels.oscript:71`) or `timestamp > $expiry_ts` (`test/samples/ico_with_milestones.oscript:66`) evaluate against this manipulated value, letting the poster pass or fail the deadline check contrary to the AA author's real-time intent.

Note: I was not able to fully verify the exact maximum practical "staleness" window achievable in the current stable MC (e.g., how many stable balls can lag behind the tip while still satisfying `max_parent_limci`), since that depends on runtime DAG state not visible via static code search; a live/testnet PoC would be needed to quantify exploitable drift precisely.

### Citations

**File:** validation.js (L720-738)
```javascript
			conn.query(
				"SELECT is_stable, is_on_main_chain, main_chain_index, ball, timestamp, (SELECT MAX(main_chain_index) FROM units) AS max_known_mci \n\
				FROM units LEFT JOIN balls USING(unit) WHERE unit=?", 
				[last_ball_unit], 
				function(rows){
					if (rows.length !== 1) // at the same time, direct parents already received
						return callback("last ball unit "+last_ball_unit+" not found");
					var objLastBallUnitProps = rows[0];
					// it can be unstable and have a received (not self-derived) ball
					//if (objLastBallUnitProps.ball !== null && objLastBallUnitProps.is_stable === 0)
					//    throw "last ball "+last_ball+" is unstable";
					if (objLastBallUnitProps.ball === null && objLastBallUnitProps.is_stable === 1)
						throw Error("last ball unit "+last_ball_unit+" is stable but has no ball");
					if (objLastBallUnitProps.is_on_main_chain !== 1)
						return callback("last ball "+last_ball+" is not on MC");
					if (objLastBallUnitProps.ball && objLastBallUnitProps.ball !== last_ball)
						return callback("last_ball "+last_ball+" and last_ball_unit "+last_ball_unit+" do not match");
					objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index;
					objValidationState.last_ball_timestamp = objLastBallUnitProps.timestamp;
```

**File:** validation.js (L740-741)
```javascript
					if (objValidationState.max_parent_limci < objValidationState.last_ball_mci)
						return callback("last ball unit "+last_ball_unit+" is not included in parents, unit "+objUnit.unit);
```

**File:** formula/evaluation.js (L1046-1052)
```javascript
			case 'mci':
				cb(new Decimal(mci));
				break;

			case 'timestamp':
				cb(new Decimal(objValidationState.last_ball_timestamp));
				break;
```

**File:** test/samples/ico_with_milestones.oscript (L65-66)
```text
			{ // finish the ICO
				if: `{ trigger.data.finish AND (trigger.address == $control_address OR timestamp > $expiry_ts) }`,
```

**File:** test/samples/payment_channels.oscript (L68-72)
```text
			{ // confirm closure
				if: `{ trigger.data.confirm AND var['close_initiated_by'] }`,
				init: `{
					if (!($bFromParties AND var['close_initiated_by'] != $party OR timestamp > var['close_start_ts'] + $close_timeout))
						bounce('too early');
```

**File:** test/samples/futures_contract.oscript (L59-68)
```text
			{ // record blackswan event
				if: `{ trigger.data.blackswan AND !var['blackswan'] AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA']] < 25 AND timestamp < 1556668800 }`,
				messages: [{
					app: 'state',
					state: `{
						var['blackswan'] = 1;
						response['blackswan'] = 1;
					}`
				}]
			},
```
