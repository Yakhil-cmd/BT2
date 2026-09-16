### Title
Predictable/grindable "randomness" via `number_from_seed()` allows AA trigger senders to bias outcomes in lottery/NFT-style AAs - (File: `formula/evaluation.js`)

### Summary
The oscript function `number_from_seed()` derives a pseudo-random number by SHA-256 hashing an author-supplied seed and mapping it into a range. [1](#0-0)  Because the seed is typically built from data that is fully known to the party composing the trigger unit *before* it is ever broadcast (e.g. `trigger.unit`, `trigger.data`, `params`, or other values controlled/computable by the trigger sender), an attacker can compose many candidate trigger units off-chain, locally evaluate what `number_from_seed()` would return for each, and only broadcast the one unit that yields a favorable "random" outcome. This is the exact bug class described in the referenced report: on-chain "randomness" that is actually a deterministic function of attacker-known/controlled inputs can be brute-forced/grinded to subvert fairness, e.g., in a lottery/raffle AA or an AA that redeems a "random" item (NFT, prize, discount) from a pool.

### Finding Description
`number_from_seed` computes:
```
hash = sha256(seed)
num  = hash-derived-fraction-in-[0,1) mapped to [min, max]
``` [2](#0-1) 

This is a deterministic, publicly-computable function - there is no commitment step and no verifiable secret input (unlike `vrf_verify`, which exists specifically to let an oracle produce unpredictable-but-verifiable randomness using a private key) [3](#0-2) . The oscript grammar exposes `number_from_seed` as a general-purpose primitive that AA authors can feed with any expression, including values that are visible/controllable to the very party who will benefit from the outcome, such as `trigger.data`, `trigger.unit`, `params`, or `this_address`/`response_unit` combinations, as shown in the formula test suite [4](#0-3) .

If an AA author builds a "random selection" feature (e.g., "redeem a random NFT from the vault", "spin a wheel", "pick a random winner among contributors") using `number_from_seed(seed)` where any component of `seed` is known to the trigger's author prior to broadcasting the trigger unit (this includes the trigger's own `unit` hash, since the unit hash is fully determined by its content, which the composer controls before submission, and `trigger.data`, which is directly attacker-supplied), then the attacker can:
1. Locally compose a trigger unit (without broadcasting).
2. Compute `trigger.unit` (its own hash) and evaluate the AA's `number_from_seed` formula off-chain using the same deterministic algorithm.
3. Only broadcast the trigger if the computed outcome is favorable (e.g., yields the specific NFT/prize they want), discarding unfavorable candidates without any on-chain cost.

This is a stronger version of the report's brute-force-via-revert exploit: in EVM, an attacker's contract had to actually revert a failed attempt on-chain (or use `staticcall`/local node simulation); in Obyte, the entire "randomness" can be precomputed for free before ever broadcasting a unit, since the formula and the unit-hashing algorithm are public and deterministic, and no on-chain state (like a future block hash unknown until mined) is truly required as an unpredictable ingredient unless the AA author deliberately incorporates something unknown at composition time.

### Impact Explanation
This can directly cause AA fund loss or unfair value transfer: an attacker can guarantee winning a "random" prize, always redeeming the most valuable NFT/asset from a shared pool, or always winning a raffle/lottery AA, at the expense of honest participants and/or the AA's balance, matching the "AA fund loss" impact category. Any AA design relying on `number_from_seed` with attacker-influenceable or attacker-precomputable seed material for high-value random selection is vulnerable to this manipulation.

### Likelihood Explanation
Likelihood depends on AA-author usage rather than a core protocol flaw: `number_from_seed` itself behaves as documented (a deterministic seeded hash), so this is a misuse-prone primitive rather than a bug in validation/consensus. However, because `number_from_seed` is the only documented general "randomness" primitive besides the oracle-based `vrf_verify`, and its natural/tempting seed inputs (`trigger.unit`, `trigger.data`, `mci`, `timestamp`) are all either attacker-controlled or attacker-predictable at composition time, AA authors building games, raffles, or randomized-distribution features are likely to fall into this trap, as evidenced by real-world AA samples in the repo that build game/lottery-style logic around deterministic trigger-derived values (e.g., `test/samples/51_attack_game.oscript`, which reveals contributions/winner logic driven by trigger data and state) [5](#0-4) .

### Recommendation
- Document prominently (and ideally enforce via linting/AA validation warnings) that `number_from_seed` must never use a seed that is known or computable by the party who benefits from the outcome before the triggering unit is broadcast (this includes `trigger.unit`, `trigger.data`, or any locally-composable value).
- Recommend/require AA authors needing unpredictable, fair randomness to use `vrf_verify` with an oracle-held private key, or a commit-reveal pattern spanning two separate trigger units (commit a hash first, reveal the preimage in a later trigger only after the "random" seed source, e.g. a future stable MC unit or oracle price, becomes fixed and unknowable at commit time).
- Consider adding a dedicated safe randomness primitive that derives entropy from data unknown to any party at the time of trigger composition (e.g., derived from the hash of a future stable MC unit that isn't yet chosen when the trigger is broadcast), similar in spirit to `vrf_verify`.

### Proof of Concept
Illustrative vulnerable AA pattern (schematic oscript):
```
{ // vault AA: "redeem a random NFT"
  messages: [{
    app: 'state',
    state: `{
      $index = number_from_seed(trigger.unit, 0, var['pool_size'] - 1);
      $nft = var['nft_' || $index];
      ...
    }`
  }]
}
```
Because `trigger.unit` is the hash of the trigger unit itself, and the attacker fully controls and can compute the content/hash of their own unit before broadcasting it (standard wallet unit-composition flow), the attacker can:
1. Draft many trigger units locally (varying e.g. an unused `trigger.data` nonce field to change `trigger.unit`).
2. For each draft, compute `sha256(trigger.unit)` and replicate the `number_from_seed` mapping formula shown in `formula/evaluation.js:1893-1918` to predict `$index` off-chain.
3. Broadcast only the draft whose predicted `$index` maps to the most desirable NFT, guaranteeing a favorable outcome every time, with zero cost for discarded drafts.

### Citations

**File:** formula/evaluation.js (L1736-1766)
```javascript
			case 'vrf_verify':
				var seed = arr[1];
				var proof = arr[2];
				var pem_key = arr[3];
				evaluate(seed, function (evaluated_seed) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isNonemptyString(evaluated_seed))
						return setFatalError("bad seed in vrf_verify", { arr }, false, cb);
					evaluate(proof, function (evaluated_proof) {
						if (fatal_error)
							return cb(false);
						if (!ValidationUtils.isNonemptyString(evaluated_proof))
							return setFatalError("bad proof string in vrf_verify", { arr }, false, cb);
						if (evaluated_proof.length > 1024)
							return setFatalError("proof is too large", { arr }, false, cb);
						if (!ValidationUtils.isValidHexadecimal(evaluated_proof))
							return setFatalError("bad signature string in vrf_verify", { arr }, false, cb);
						evaluate(pem_key, function (evaluated_pem_key) {
							if (fatal_error)
								return cb(false);
							signature.validateAndFormatPemPubKey(evaluated_pem_key, "RSA", function (error, formatted_pem_key){
								if (error)
									return setFatalError("bad PEM key in vrf_verify: " + error, { arr }, false, cb);
								var result = signature.verifyMessageWithPemPubKey(evaluated_seed, evaluated_proof, formatted_pem_key, bPostPemCurvesFix);
								return cb(result);
							}, bPostPemCurvesFix);
						});
					});
				});
				break;
```

**File:** formula/evaluation.js (L1872-1920)
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
				break;
```

**File:** test/formula.test.js (L2407-2432)
```javascript
test('number_from_seed', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT" };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `number_from_seed("vvv")`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, '0.240886496464544');
		t.deepEqual(count_ops, 2);
	})
});

test('int number_from_seed', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT" };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `number_from_seed("vvv", 99)`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, 24);
		t.deepEqual(count_ops, 2);
	})
});

test('int number_from_seed with min', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT" };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `number_from_seed("vvv", 10, 109)`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, 34);
		t.deepEqual(count_ops, 2);
	})
});
```

**File:** test/samples/51_attack_game.oscript (L66-95)
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
			},
```
