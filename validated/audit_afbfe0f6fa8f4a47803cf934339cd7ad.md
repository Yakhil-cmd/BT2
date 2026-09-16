### Title
Grindable/predictable pseudo-randomness via `number_from_seed()` in oscript — ([File: formula/evaluation.js])

### Summary
Obyte's AA scripting language exposes a built-in `number_from_seed()` primitive that derives a "random" number by SHA-256-hashing an author-supplied seed. If an AA definition seeds this function with data that is known or controllable by the unprivileged AA trigger sender before the triggering unit is broadcast (e.g. `trigger.unit`, `timestamp`, `trigger.data`, or `mc_unit`), the trigger sender can grind many candidate units off-chain, compute the resulting pseudorandom value for each, and only broadcast the trigger that yields a favorable outcome. This mirrors the reported Holograph pattern where an attacker repeatedly recomputed `block.number`/`block.timestamp`-derived randomness until the result was favorable before submitting the real call.

### Finding Description
`number_from_seed` is implemented in the oscript evaluator as a straightforward `sha256(seed)`-derived float scaled to a range: [1](#0-0) 

The seed is any value the AA formula computes, and AA authors are free to construct it from trigger-controlled or otherwise attacker-predictable inputs such as `trigger.unit`, `trigger.data`, or `timestamp`. The validation layer only checks the arity/type of the arguments, not whether the seed source is unpredictable: [2](#0-1) 

Because a unit's own hash (`trigger.unit`) is fully determined by content the sender controls (message payloads, parents chosen from among valid candidates, and the timestamp it sets when composing), and `timestamp`/`mc_unit` are also either sender-influenced or knowable in advance of broadcast, an unprivileged trigger sender can:
1. Compose many different valid candidate trigger units locally (varying parents/timestamp/data) without broadcasting them.
2. For each candidate, compute the exact `number_from_seed()` value the AA would derive (since the seed and the sha256 algorithm are public and deterministic).
3. Only broadcast the one unit whose derived value produces a favorable game/lottery/selection outcome in the AA.

This is functionally identical to the Holograph finding's "retry off-chain until favorable, then submit" pattern; the difference is that ocore has no mempool "resubmit" step — the grinding happens entirely off-chain before the single broadcast, which is arguably even easier for the attacker since there's no on-chain retry cost at all.

The codebase's own sample AA game contracts (e.g. `test/samples/51_attack_game.oscript`, `test/ojson.test.js`) use majority-stake/challenge-period patterns rather than `number_from_seed`, showing awareness of griefing/gaming concerns in AA game design, but `number_from_seed` itself carries no built-in warning or restriction preventing use of a grindable seed such as `trigger.unit` or `timestamp`. [3](#0-2) 

### Impact Explanation
Any AA that uses `number_from_seed()` seeded (directly or derivably) from trigger-controlled data to decide fund-affecting outcomes (lotteries, games, randomized payouts, winner selection) is vulnerable to outcome manipulation by the triggering party. This is a direct AA fund-loss / unfair-fund-distribution vector: the attacker can guarantee winning payouts or bias probabilistic distributions, draining AA balances that should have been protected by genuine unpredictability. Because AAs are commonly used for gambling/lottery dApps built on ocore, this bad-randomness pattern in the base scripting language is a realistic and directly reachable root cause for supply/fund-loss issues in any dependent AA, triggered by nothing more than a normal trigger unit from an ordinary user.

### Likelihood Explanation
Likelihood depends entirely on how individual AA authors use `number_from_seed()` — the language primitive does not enforce or suggest an unpredictable seed source. Given that `trigger.unit`, `trigger.data`, and `timestamp` are the most naturally available values inside a trigger handler, and no documentation-enforced restriction against using them as a seed exists in the validator, this is a foreseeable footgun that has previously been the exact bug class flagged in the referenced external report (bad source of randomness re-rollable by the calling party). Any single unprivileged unit poster (the AA trigger sender) can reach and exploit this without any privileged role.

### Recommendation
- In `formula/validation.js`, restrict or flag `number_from_seed()` usage when the seed expression is provably derived only from values known to the trigger sender before broadcast (`trigger.unit`, `timestamp`, `trigger.data`, `mc_unit`), and document clearly that a safe seed must incorporate data unknown to the sender at composition time (e.g., a committed-then-revealed value, or a value derived after the trigger unit is already stable, such as content only knowable post-stabilization).
- Provide/encourage a commit-reveal helper pattern in oscript documentation and, ideally, a built-in verifiable-randomness primitive (matching the report's own suggestion of a VRF-style approach) so AA authors are not left to hand-roll grindable seeds.
- Add lint-style warnings in `formula/validation.js` when `number_from_seed` args reference `trigger.*`, `timestamp`, or `mc_unit` directly, since these are attacker/sender predictable at the time of unit composition.

### Proof of Concept
1. Deploy an AA whose payout formula includes:
```
{
  $r = number_from_seed(trigger.unit, 0, 1);
  if ($r == 1)
    // pay full jackpot to trigger.address
}
```
2. As the trigger sender, before broadcasting, compose the trigger unit off-chain (choosing message content/parents/timestamp per normal wallet composition), compute its resulting unit hash, and evaluate `sha256(unit_hash)` locally exactly as `number_from_seed` would.
3. If the computed value does not satisfy the winning condition, discard this candidate unit (never broadcast it) and recompose with different parents/timestamp/content to get a new candidate hash.
4. Repeat until a candidate unit is found whose derived pseudorandom value is favorable, then broadcast only that unit.
5. The AA pays out based on the attacker-selected favorable "random" outcome, resulting in unauthorized fund loss from the AA's balance.

### Citations

**File:** formula/evaluation.js (L1893-1898)
```javascript
						var seed = evaluated_params[0];
						var hash = crypto.createHash("sha256").update(seed.toString(), "utf8").digest("hex");
						var head = hash.substr(0, 16);
						var nominator = new Decimal("0x" + head);
						var denominator = new Decimal("0x1" + "0".repeat(16));
						var num = nominator.div(denominator); // float from 0 to 1
```

**File:** formula/validation.js (L888-903)
```javascript
			case 'number_from_seed':
				complexity++;
				if (arr[1].length === 0)
					return cb("no arguments of number_from_seed");
				if (arr[1].length > 3)
					return cb("too many params in number_from_seed");
				if (typeof arr[1][1] === 'string' || typeof arr[1][2] === 'string')
					return cb("min or max is a string");
				async.eachSeries(
					arr[1],
					function (param, cb2) {
						evaluate(param, cb2);
					},
					cb
				);
				break;
```

**File:** test/samples/51_attack_game.oscript (L66-94)
```text
			{ // contribute to a team
				if: `{trigger.data.team AND !$bFinished}`,
				init: `{
					if (!var['team_' || trigger.data.team || '_asset'])
						bounce('no such team');
					if (var['winner'] AND var['winner'] == trigger.data.team)
						bounce('contributions to candidate winner team are not allowed');
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: `{var['team_' || trigger.data.team || '_asset']}`,
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.output[[asset=base]]}"}
							]
						}
					},
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
				]
```
