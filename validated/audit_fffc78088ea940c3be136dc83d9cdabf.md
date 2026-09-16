### Title
Autonomous Agents relying on the `timestamp` keyword for deadlines trust an author-controllable "last stable ball timestamp" rather than true wall-clock time - ([File: validation.js])

### Summary
The reported issue is about smart contracts using `block.timestamp` as a deadline, which a miner can manipulate/delay to their advantage. In ocore, the oscript `timestamp` keyword available to AA formulas is not the real-time clock — it is set to `objValidationState.last_ball_timestamp`, i.e., the `timestamp` field of whatever unit the trigger's *last_ball_unit* points to. That value is chosen by the **author of the unit** that becomes the referenced last ball, subject only to loose bounds (must not be too far in the future, must not decrease from parent). This makes AA deadline/timeout logic that uses `timestamp` (as documented in the shipped oscript examples: payment channels, ICOs, futures contracts) analogous to the `block.timestamp`-for-deadline weakness in the report: any unprivileged unit author who controls which last-ball/parents are referenced by a chain of units can influence the "timestamp" value an AA trigger observes, rather than it always tracking real elapsed time.

### Finding Description
`timestamp` in oscript resolves to `last_ball_timestamp`, set from the units table when parents/last_ball are validated: [1](#0-0) 

The only constraints placed on a unit's own `timestamp` field are a small future-skew tolerance and non-retreat relative to the direct parent: [2](#0-1) [3](#0-2) 

There is no requirement that a unit's `timestamp` (and therefore any subsequent unit's `last_ball_timestamp`) closely track real wall-clock time beyond "not too far in the future" — an author can post units with a timestamp that lags behind real time, and later reference that stale, already-stable ball as `last_ball_unit` for a trigger unit, as long as the last-ball MCI does not retreat relative to their own previous unit and remains included in their chosen parents: [4](#0-3) 

AA authors are documented to rely on this `timestamp` value for enforceable deadlines/timeouts, e.g. a payment-channel closing timeout: [5](#0-4) 

an ICO expiry / milestone gate: [6](#0-5) 

and a futures-contract maturity/blackswan check: [7](#0-6) 

In each case, the AA's `if`/`init` guards compare `timestamp` (i.e. `last_ball_timestamp`) against a fixed threshold to decide whether a time-gated branch (early payout, milestone release, channel-closure confirmation, blackswan declaration) is allowed. Because `timestamp` is fundamentally the self-reported clock value embedded by whichever unit author's unit became the referenced last ball — not a consensus-audited wall clock — a party who can influence which stable unit gets used as `last_ball_unit` for their own trigger (by choosing older/newer eligible free parents, or by delaying broadcast of a pre-composed unit until a more favorable last-ball becomes available) can shift the effective "current time" seen by the AA relative to actual elapsed time, similarly to how a miner can nudge `block.timestamp` in the original report.

### Impact Explanation
An attacker (a normal AA trigger sender, no special privileges) can attempt to either accelerate or delay the effective `timestamp` an AA observes, relative to real elapsed time, when composing their own trigger unit. Depending on the specific AA logic, this can:
- Force an early "deadline expired" branch (e.g. confirm channel closure before the real timeout, per `test/samples/payment_channels.oscript` lines 68-75), causing the counterparty to lose the ability to dispute and resulting in fund loss to one party.
- Delay a "deadline expired" branch to keep an ICO/futures contract active longer than intended, or conversely trigger milestone/blackswan payouts prematurely, causing AA fund loss or misallocation.

This falls into the "AA fund loss" impact category, matching the analog's root cause (deadline enforcement built on an attacker-influenceable timestamp source rather than a tamper-resistant clock).

### Likelihood Explanation
Likelihood is constrained by how much slack an author can realistically get between the real wall-clock time and the `timestamp`/`last_ball_timestamp` they can reference: the "too far into the future" check bounds forward drift to a few seconds (`conf.max_seconds_into_the_future_to_accept`, default 5s), and the last-ball MCI cannot retreat for a given author's chain. However, there is no corresponding lower bound forcing `last_ball_timestamp` to track real time closely from below — a unit's own `timestamp` can lag arbitrarily behind wall clock as long as free eligible units with older stable last-balls remain referenceable as parents, which is more likely during periods of low network throughput. This makes the attack opportunistic rather than reliably exploitable to a large degree in all conditions, but it is directly reachable by any ordinary unit/trigger author with no special access.

### Recommendation
For deadline-sensitive AA logic (channel timeouts, ICO expiries, milestone gates), avoid relying solely on the self-reported `timestamp`/`last_ball_timestamp` value as an authoritative wall clock. Where feasible, require deadlines to be validated against multiple independently-attested markers (e.g., MCI-based aging with `age` operator combined with `timestamp`, or require a minimum number of intervening stable units) so that a single unit author cannot cheaply skew the effective "current time" observed by the AA. At the protocol level, consider tightening the bound between a unit's declared `timestamp` and real-time progression of the main chain (e.g., a maximum allowed staleness for `last_ball_unit`, not just a "not in the future" and "not retreating" check).

### Proof of Concept
1. AA `X` is deployed with a time-gated branch such as `test/samples/payment_channels.oscript`'s "confirm closure" case, which checks `timestamp > var['close_start_ts'] + $close_timeout` at trigger-init time ( [8](#0-7) ).
2. Party A (either channel participant, an unprivileged trigger sender) constructs their confirmation-trigger unit but deliberately selects parents/`last_ball_unit` referencing an older stable ball whose `timestamp` value is favorably close to (but just over) `var['close_start_ts'] + $close_timeout`, even though real wall-clock time has not yet reached that point, exploiting the fact that only future-drift and non-retreat are enforced on `timestamp` ( [2](#0-1)  and [3](#0-2) ).
3. When the AA evaluates `timestamp` (bound to `last_ball_timestamp` from that referenced ball, [1](#0-0) ), the deadline check passes even though the intended real-time cooling-off period has not fully elapsed, letting Party A force channel closure/settlement earlier than the honest protocol intends.

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

**File:** validation.js (L693-694)
```javascript
				if (objUnit.version !== constants.versionWithoutTimestamp && objUnit.timestamp < objParentUnitProps.timestamp)
					return cb("timestamp decreased from parent " + parent_unit);
```

**File:** validation.js (L737-739)
```javascript
					objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index;
					objValidationState.last_ball_timestamp = objLastBallUnitProps.timestamp;
					objValidationState.max_known_mci = objLastBallUnitProps.max_known_mci;
```

**File:** test/samples/payment_channels.oscript (L60-75)
```text
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
						bounce('too early');
					$finalBalanceA = var['balanceA'] - var['spentByA'] + var['spentByB'];
					$finalBalanceB = var['balanceB'] - var['spentByB'] + var['spentByA'];
				}`,
```

**File:** test/samples/ico_with_milestones.oscript (L65-76)
```text
			{ // finish the ICO
				if: `{ trigger.data.finish AND (trigger.address == $control_address OR timestamp > $expiry_ts) }`,
				messages: [
					{
						app: 'state',
						state: `{
							var['finished'] = 1;
							var['total'] = balance[base];
							response['total'] = balance[base];
						}`
					}
				]
```

**File:** test/samples/futures_contract.oscript (L59-90)
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
						// data_feed will abort if the exchange rate not posted yet
						$exchange_rate = data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']];
						$bytes_per_usd_asset = min(50/$exchange_rate/2, 1);
```
