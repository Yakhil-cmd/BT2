## Finding

### Title
AA `timestamp` Builtin Is Attacker-Selectable via Last-Ball Choice, Enabling Time-Lock/Vesting Bypass in AAs - (File: formula/evaluation.js, aa_composer.js, parent_composer.js, validation.js)

### Summary
The oscript `timestamp` keyword used inside Autonomous Agent (AA) formulas does not reflect a trustworthy, tamper-resistant "current time." It resolves to `objValidationState.last_ball_timestamp`, which is simply the `timestamp` field of whatever unit the AA-trigger unit's author designated as `last_ball_unit`. Because the primary-trigger sender freely composes their own unit (including choosing `parent_units` and thereby the `last_ball`/`last_ball_unit` it is allowed to reference), they have meaningful latitude to pick a stable ball with a timestamp that is more favorable to them than genuine current time, then submit the trigger. Any AA that implements vesting cliffs, unlock schedules, or expiry-based logic (a common oscript pattern, e.g. `timestamp > $expiry_ts` seen in the bundled `ico_with_milestones.oscript` / `futures_contract.oscript` samples) can have its time-based branch manipulated by the trigger's own author.

### Finding Description
In `formula/evaluation.js`, the `timestamp` operator simply returns the last-ball timestamp of the validation state, not any independently-verified wall-clock time: [1](#0-0) 

That `last_ball_timestamp` is populated when the AA trigger is processed, directly from the timestamp of the unit chosen as `objMcUnit` (the unit backing `last_ball_unit`): [2](#0-1) 

Crucially, the unit author (not any witness/miner-neutral process) is the one who picks which already-stable ball to reference as `last_ball`/`last_ball_unit` when they build their trigger unit. The standard composer's parent-and-last-ball selection logic (`parent_composer.js`) merely walks from the chosen parent units to find *a* valid stable ball; the protocol itself, in `validation.js`, only enforces a **lower bound**, not that the referenced last ball be the most-recent/"current" stable ball: [3](#0-2) 

The only requirement is `max_parent_last_ball_mci <= objValidationState.last_ball_mci` — i.e., the last ball referenced must not be *older* than what the chosen parents already commit to. There is no requirement that it be the newest available stable ball. Combined with the parent-selection constraints (units must be otherwise-unrelated, and the unit's own `timestamp` must only be `>=` its parents' timestamps and within a few seconds of local time — a constraint on the *trigger unit's own* timestamp field, not on the referenced `last_ball_timestamp`): [4](#0-3) [5](#0-4) 

An attacker who builds their trigger unit outside the convenience wallet composer (i.e., directly crafting parents/last_ball, which the protocol permits) can deliberately choose an older (or, within the freshest window, the most current) stable ball as `last_ball`, thereby controlling the `timestamp` value an AA's oscript logic will observe — analogous to a miner nudging `block.timestamp` in the referenced Solidity report, but here the "nudging" party is the unprivileged trigger sender itself, and the achievable drift is bounded only by DAG stability/ordering rules rather than a small a few-second window.

### Impact Explanation
Any AA that gates fund release, vesting cliffs, unlock schedules, or option/futures-style expiry on the `timestamp` builtin (a documented and encouraged oscript pattern, as shown in the bundled sample contracts using `timestamp > $expiry_ts` / `timestamp < 1556668800`) can have those checks satisfied or blocked at a time of the attacker's choosing rather than at the true current network time. This can lead to premature release of vested/locked AA funds, bypass of cliffs/expiry protections, or denial of legitimate time-gated operations — i.e., concrete AA fund loss or freezing.

### Likelihood Explanation
Exploitation only requires composing a custom trigger unit (not the reference wallet's automatic composer) that selects an eligible parent set/last_ball satisfying the DAG-ordering and non-retreating constraints in `validateParents`. No privileged network role (witness/hub/miner) is needed — any ordinary AA-trigger sender can attempt this, making it reachable from a fully unprivileged actor.

### Recommendation
AAs that need tamper-resistant elapsed-time semantics should not rely solely on the bare `timestamp` builtin for fine-grained scheduling; the protocol could additionally expose/require checks bounding how far `last_ball_timestamp` may lag real submission time relative to the sender's other recent activity, or oscript documentation/tooling should explicitly warn AA authors that `timestamp` reflects the trigger author's chosen last ball, not verified wall-clock time, and encourage bounding acceptable drift within the AA logic itself (e.g., cross-checking against `mci` deltas with known average block times, or requiring multiple independent time attestations).

### Proof of Concept
1. Author writes an AA vesting contract using: `if (timestamp - var['start_ts'] > $cliff_period) { ... release ... }`.
2. An attacker who is a normal, unprivileged participant (beneficiary of the vesting or any address wishing to force branch selection) crafts a trigger unit by hand, choosing `parent_units` and `last_ball_unit`/`last_ball` pointing to a stable ball whose `timestamp` already satisfies `> $cliff_period`, even though genuine wall-clock time has not reached the cliff — subject only to `validateParents`'s non-retreating last-ball-mci constraint [3](#0-2) .
3. The unit passes validation (no rule forces `last_ball` to be the most recent stable ball or close to real time), and `aa_composer.js` sets `objValidationState.last_ball_timestamp = objMcUnit.timestamp` from that chosen ball [2](#0-1) .
4. The AA's oscript evaluates `timestamp` as that attacker-chosen value [1](#0-0) , causing the cliff/vesting check to pass prematurely and releasing funds early.

### Citations

**File:** formula/evaluation.js (L1050-1052)
```javascript
			case 'timestamp':
				cb(new Decimal(objValidationState.last_ball_timestamp));
				break;
```

**File:** aa_composer.js (L450-453)
```javascript
	var objValidationState = {
		last_ball_mci: mci,
		last_ball_timestamp: objMcUnit.timestamp,
		mc_unit: objMcUnit.unit,
```

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

**File:** validation.js (L690-694)
```javascript
		objUnit.parent_units, 
		function(parent_unit, cb){
			storage.readUnitProps(conn, parent_unit, function(objParentUnitProps){
				if (objUnit.version !== constants.versionWithoutTimestamp && objUnit.timestamp < objParentUnitProps.timestamp)
					return cb("timestamp decreased from parent " + parent_unit);
```
