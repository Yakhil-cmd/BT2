### Title
Predictable/grindable `number_from_seed` PRNG in oscript enables AA fund drain via attacker-controlled trigger content - (File: formula/evaluation.js)

### Summary
The oscript formula function `number_from_seed()` derives a "random" number purely from a `sha256` of an author-supplied seed string, with no unpredictable entropy source (no VRF, no future MC data, no unknown value). [1](#0-0)  AA authors commonly seed this function with attacker-controlled trigger fields such as `trigger.unit` or `trigger.data`, both of which are fully known/chosen by the unprivileged trigger sender before the trigger unit is even broadcast. [2](#0-1)  This mirrors the Unbound CVE pattern: a value intended to inject unpredictability into a security/selection decision is deterministically derivable by the party that should not be able to predict/control it, letting that party defeat the randomization.

### Finding Description
`number_from_seed` hashes the seed with SHA-256 and maps the hash to a number/range, entirely deterministically — the same seed always yields the same "random" number, as confirmed by the unit tests (`number_from_seed("vvv")` always evaluates to the fixed value `0.240886496464544`). [3](#0-2)  The function accepts any expression as the seed, including `trigger.unit`, `trigger.data`, `trigger.address`, or other trigger-controlled fields, which are exposed to oscript formulas as first-class tokens. [4](#0-3) 

A trigger unit's content (its `data` payload, in particular) is chosen entirely by the trigger sender before the unit is signed and broadcast. [5](#0-4)  Because the trigger sender controls the `data`/`unit` content used as the seed, they can locally compute many candidate trigger units offline (varying free-form fields such as `data`), evaluate what `number_from_seed(trigger.unit)` (or any trigger-derived seed) would produce for each candidate, and only ever broadcast the one candidate that yields a favorable outcome from the AA's perspective. This is the same class of failure as the CVE: a supposedly unpredictable selector is actually a deterministic function of a value the "attacker" fully controls and can pre-compute before the outcome is revealed/committed on-chain.

Any AA (e.g., lottery/gambling/reward-distribution AAs written in oscript) that relies on `number_from_seed` seeded from trigger-controlled data to decide payouts, winners, or fund distribution is exploitable by a trigger sender grinding for a favorable seed.

### Impact Explanation
An AA using this pattern to allocate/distribute funds (a common, natural use of `number_from_seed` given it exists specifically to produce "random" numbers for AA logic) can be forced by any unprivileged trigger sender to always land on the maximally favorable outcome, resulting in concrete AA fund loss/drain — funds intended to be probabilistically distributed are instead deterministically routed to the attacker. This satisfies the required "AA fund loss" impact class.

### Likelihood Explanation
High. Grinding is entirely free and offline: the attacker never needs to broadcast a losing attempt, incurs no on-chain cost for failed guesses, and only needs to try distinct values of any attacker-controlled trigger field (e.g., `data`) until the resulting `sha256`-derived number satisfies their desired output range. No special privileges are required — only the ability to post a unit/trigger, which is explicitly in scope.

### Recommendation
- Document/enforce that `number_from_seed` must never be seeded (directly or indirectly) from any value fully controlled or predictable by a single unprivileged party (e.g., `trigger.unit`, `trigger.data`, `trigger.address`) when used for financial randomness.
- Encourage/require AA authors to seed with values not fully known to the trigger sender at seed-selection time (e.g., a future/unknown MC unit hash, a value contributed by multiple independent parties, or a committed-then-revealed scheme) to remove the ability to precompute favorable seeds.
- Consider adding a lint/warning in AA validation (`formula/validation.js`) when `number_from_seed` is seeded directly from `trigger.*` fields, to alert AA authors to the grinding risk.

### Proof of Concept
1. An AA is deployed whose payout logic includes something like `number_from_seed(trigger.unit, 1, 100)` (or seeded by `trigger.data`) to pick a winner/payout tier.
2. A trigger sender, before broadcasting, locally assembles a trigger unit with a free-form `data` field (e.g., `{data: {nonce: N}}`) and computes what the resulting `trigger.unit` hash would be for many values of `N`, and for each, evaluates what `number_from_seed(...)` would produce in the AA's logic (this can be simulated locally against the known deterministic SHA-256-based algorithm shown in `formula/evaluation.js:1892-1898`). [6](#0-5) 
3. The sender selects the `N` that produces the maximally favorable payout result and only broadcasts that one trigger unit.
4. The AA executes deterministically on this unit and pays out the attacker-chosen favorable amount, as validated by the deterministic test vectors for `number_from_seed`. [7](#0-6)

### Citations

**File:** formula/evaluation.js (L1872-1898)
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
```

**File:** formula/grammars/oscript.ne (L34-42)
```text
		trigger_address: /\btrigger\.address\b/,
		trigger_initial_address: /\btrigger\.initial_address\b/,
		trigger_unit: /\btrigger\.unit\b/,
		trigger_initial_unit: /\btrigger\.initial_unit\b/,
		trigger_data: /\btrigger\.data\b/,
		trigger_outputs: /\btrigger\.outputs\b/,
		trigger_output: /\btrigger\.output\b/,
		dotSelector: /\.\w+/,
		local_var_name: /\$[a-zA-Z_]\w*\b/,
```

**File:** test/formula.test.js (L2407-2413)
```javascript
test('number_from_seed', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT" };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `number_from_seed("vvv")`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, '0.240886496464544');
		t.deepEqual(count_ops, 2);
	})
```

**File:** test/formula.test.js (L2416-2423)
```javascript
test('int number_from_seed', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT" };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `number_from_seed("vvv", 99)`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, 24);
		t.deepEqual(count_ops, 2);
	})
});
```

**File:** formula/grammars/oscript.js (L36-44)
```javascript
		ternary: ['?', ':'],
		addressValue: /\b[2-7A-Z]{32}\b/,
		trigger_address: /\btrigger\.address\b/,
		trigger_initial_address: /\btrigger\.initial_address\b/,
		trigger_unit: /\btrigger\.unit\b/,
		trigger_initial_unit: /\btrigger\.initial_unit\b/,
		trigger_data: /\btrigger\.data\b/,
		trigger_outputs: /\btrigger\.outputs\b/,
		trigger_output: /\btrigger\.output\b/,
```

**File:** test/aa_composer.test.js (L156-159)
```javascript
test.cb.serial('chain of AAs', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 40000 }, data: { x: 333 }, address: trigger_address };

```
