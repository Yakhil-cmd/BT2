### Title
AA "randomness" derived from attacker-controlled trigger data/unit hash via `number_from_seed`/`sha256` can be pre-computed and grinded by the trigger sender at no cost - ([File: formula/evaluation.js])

### Summary
Oscript exposes `number_from_seed(seed[, min[, max]])` and `sha256(...)` as the only pseudo-randomness primitives available to AA authors. Both are pure deterministic functions of their input. If an AA formula derives its "random" value from data that the trigger sender fully controls before broadcasting (e.g. `trigger.data`, or the trigger unit's own hash `trigger.unit`), the sender can compute the resulting value locally, try many candidate unit contents off-chain, and only ever broadcast the one unit whose derived value is favorable. Unlike a smart-contract chain with global mempool ordering, no gas/fee is spent for the "failed" candidates because they are never submitted — this is functionally identical to Beebots' `randomIndex()` grinding described in the report, just performed off-chain instead of via Flashbots simulate-and-drop.

### Finding Description
`number_from_seed` computes a pseudo-random number purely as `sha256(seed)`: [1](#0-0) 

The seed is any value the AA formula author decides to hash, most naturally something derived from the trigger, e.g. `trigger.data.nonce`, `trigger.unit`, or `sha256(trigger.unit)`. Crucially, `trigger` is built directly from the unit the calling account posts: [2](#0-1) 

`trigger.data` is copied verbatim from the `data` message of the unit the sender authored, and `trigger.unit` is that unit's own hash. Both are entirely under the sender's control before the unit is signed and broadcast: the sender can insert or vary a `data` payload (e.g. add a dummy/nonce field), which changes the unit content and therefore both `trigger.data` and the resulting `trigger.unit` hash (`objectHash.getUnitHash`), as seen at the point the AA composer itself finalizes the unit hash after building message content: [3](#0-2) 

Because the sender constructs and signs their own trigger unit locally before ever submitting it to the network, they can:
1. Build many candidate versions of the trigger unit (varying `data`, e.g. `nonce` values), computing `sha256(seed)`/`number_from_seed` locally for each candidate exactly as the AA formula would.
2. Only sign and broadcast the one candidate unit whose seed-derived pseudo-random result is favorable to them (e.g. "won" a lottery-style AA, got a preferred token/ID, or triggered a payout branch).
3. Never pay any fee for the discarded candidates, since they are computed off-chain and never sent — no gas/Flashbots trick is even needed, since ocore has no analog to a public mempool commit for an unsent unit.

This mirrors the `Beebots.randomIndex()` finding precisely: the "randomness" is a deterministic function of data the caller fully controls prior to finalizing/broadcasting their transaction, so it provides no actual unpredictability against the party who benefits from a favorable outcome, and grinding for a favorable value costs the attacker nothing beyond local computation.

### Impact Explanation
Any AA that uses `number_from_seed`/`sha256` seeded (directly or indirectly through anything the sender controls, such as `trigger.data`, `trigger.unit`, or values computed from them) to decide payouts, asset issuance amounts/ids, winner selection, or other value-transferring branches can be gamed deterministically by the trigger sender. This can result in unauthorized/disproportionate fund extraction from the AA (e.g., always winning a lottery-style AA, always minting the most valuable asset id/denomination) — a concrete fund-loss impact for the AA and unfairness/loss for other honest participants.

### Likelihood Explanation
Any developer using these primitives for AA-side "randomness" seeded from trigger-controlled data is likely to fall into this trap, since the built-in oscript documentation function names (`number_from_seed`) invite exactly this pattern and there is no commit-reveal or oracle-based randomness primitive offered as an alternative in the language. The attack requires no special privileges — any address able to send a trigger unit to the AA can grind trigger contents locally before broadcasting.

### Recommendation
- Document/enforce that `number_from_seed`/`sha256` must never be seeded (directly or transitively) with values the trigger sender can choose or predict prior to broadcasting, including `trigger.data`, `trigger.unit`, or hashes thereof.
- Provide/require a genuinely unpredictable-to-the-sender entropy source for AAs that need randomness, such as a value from a subsequent, already-stable unit/MC data unknown at trigger-composition time (e.g., a future `mc_unit`/witness-controlled value), or a commit-reveal scheme across two separate AA triggers so the sender cannot know the seed at commit time.
- Add a linter/validation warning in AA validation (`formula/validation.js`) when `number_from_seed`/`sha256` seeds resolve to expressions built only from `trigger.*`/`params`, encouraging AA authors to use safer entropy sources.

### Proof of Concept
```
// AA pseudocode using naive "randomness"
{
  messages: [{
    app: 'payment',
    payload: {
      asset: 'base',
      outputs: [
        // pays out more if number_from_seed(trigger.unit) is favorable
        {address: "{trigger.address}", amount: "{ number_from_seed(trigger.unit, 0, 1) == 1 ? 10000 : 100 }"}
      ]
    }
  }]
}
```
Attacker flow:
1. Build the trigger unit content locally (author, payment message, and an optional `data` message with a `nonce` field), but don't sign/broadcast yet.
2. Compute the resulting `unit` hash exactly as `objectHash.getUnitHash` would (matching `aa_composer.js:1403`), and evaluate `number_from_seed(candidate_unit, 0, 1)` locally, mirroring `formula/evaluation.js:1893-1917`.
3. Adjust the `nonce` field and repeat until the local computation yields the favorable branch (`== 1`).
4. Sign and broadcast only that winning unit — the AA composer will independently recompute the same deterministic value from the now-fixed `trigger.unit`/`trigger.data` and pay out the larger amount, at no cost for the discarded candidates.

### Citations

**File:** formula/evaluation.js (L1890-1900)
```javascript
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
```

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L1399-1404)
```javascript
						objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
						const oversize_fee = (mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(objUnit, last_ball_mci, true) : 0;
						if (oversize_fee)
							objUnit.oversize_fee = oversize_fee;
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
```
