### Title
Shared, tiny (100-entry) global formula parse-cache in oscript enables repeated expensive re-parsing / cache-thrash DoS - (File: formula/common.js)

### Summary
`formula/common.js` maintains a single process-wide cache (`cache`, `formulasInCache`, `cacheLimit = 100`) that memoizes the nearley parse tree for an oscript formula string, keyed by the exact formula text. Both `formula/validation.js` and `formula/evaluation.js` share this one cache, and any attacker-controlled AA definition (posted by an unprivileged unit poster / AA author) contributes its formula strings as cache keys.

### Finding Description
`formula/evaluation.js`'s `exports.evaluate` and `formula/validation.js`'s `exports.validate` both do:
```
if(cache[formula]){ parser.results = cache[formula]; }
else { parser = new nearley.Parser(...); parser.feed(formula); formulasInCache.push(formula); cache[formula] = parser.results;
    if (formulasInCache.length > cacheLimit) { var f = formulasInCache.shift(); delete cache[f]; } }
``` [1](#0-0) [2](#0-1) 

The cache size is fixed at 100 entries, shared globally across the whole node for every AA on the system, and evicted strictly FIFO. Any AA author can post an unlimited number of distinct AA definitions (each definition is just a unit accepted through normal validation, e.g. `aa_validation.validateAADefinition`), and each AA can contain many distinct oscript formula strings across its `init`, message payload expressions, and state-update formulas. Because the cache key is the exact formula text, trivial cosmetic variation (whitespace, variable renaming, additional no-op expressions) makes every formula a unique cache key.

Since triggers to AAs are cheap to produce (any address can send a small payment to trigger an AA, subject only to `bounce_fees`), an attacker can:
1. Deploy far more than 100 distinct AAs (or reuse formulas that differ trivially) with formulas designed to be expensive to parse/evaluate by nearley (deeply nested expressions, up to the `isTooDeeplyNestedOrHasTooManyNodes` limit).
2. Continuously round-robin trigger these AAs so that, by the time any given formula is triggered again, its cache entry has already been evicted by the >100 other distinct formulas the attacker (or other legitimate users) introduced in between.

This forces the node to repeat the nearley parse (and the full formula validation/evaluation walk) on every single trigger instead of amortizing it once, for every unit posted to the network — mirroring the CVE-2024-25590 bug class where a cache that is supposed to bound repeated expensive processing is rendered ineffective by crafted/varied inputs, so the expensive work is redone on every request instead of being served from cache.

Every unit that references an AA (as trigger) or defines a new AA goes through this parse path during `validation.js`'s `validateAATrigger`/`aa_validation` pipeline and again during `aa_composer.handleTrigger`'s formula evaluation, so the cost is paid by all full nodes processing the DAG, not just the light-client-facing peer. [3](#0-2) [4](#0-3) 

### Impact Explanation
Full nodes (validators) spend CPU re-parsing/re-validating/re-evaluating oscript formulas on essentially every AA trigger unit, because the shared 100-entry cache is trivially defeated by an attacker who can cheaply mint many distinct AAs/formulas. Under sustained attack this degrades validation throughput network-wide, potentially delaying stabilization of the main chain and confirmation of new units — a network-availability impact consistent with the "no confirmation of new units" DoS class permitted by scope.

### Likelihood Explanation
Likelihood is moderate: defining new AAs and sending trigger units are unprivileged, low-cost operations available to any unit poster/AA author, and the cache size (100) is small relative to the number of AAs realistically active on a busy node, so eviction churn under adversarial traffic is plausible. However, I was not able to fully confirm (within available tool budget) the exact per-unit cost of a single nearley parse for a maximally-sized formula, nor the enforced maximum formula length/complexity limits (`MAX_AA_STRING_LENGTH`, `count_ops`, `complexity` caps referenced in `aa_validation.js`/`formula/validation.js`/`constants.js`), which would determine whether the per-parse cost is large enough to constitute a practical DoS versus a bounded, tolerable inefficiency. This uncertainty means the severity should be treated as an unconfirmed performance/availability risk rather than a proven High-impact DoS.

### Recommendation
- Scale `cacheLimit` in `formula/common.js` based on realistic AA population size, or make it per-AA-address rather than global-FIFO.
- Consider an LRU (most-recently-used) eviction policy instead of FIFO so that frequently-triggered AAs are not evicted by high-volume attacker-created one-off formulas.
- Bound/rate-limit the cost of AA definition creation (e.g., proportional fee on formula complexity/length) so that cache-defeating floods of distinct formulas are economically discouraged.
- Add profiling to confirm actual nearley parse cost for maximum-length/maximum-nesting formulas permitted by `isTooDeeplyNestedOrHasTooManyNodes` and `MAX_AA_STRING_LENGTH`, to quantify real-world DoS risk.

### Proof of Concept
Conceptual (not executed, given ask-only/no code-execution constraints):
1. Deploy 150+ distinct AAs, each with a unique oscript formula near the maximum allowed complexity/nesting (`isTooDeeplyNestedOrHasTooManyNodes` limit) and length (`MAX_AA_STRING_LENGTH`).
2. Continuously send low-value trigger units to these AAs in a round-robin pattern faster than any single AA's formula can remain resident in the shared 100-entry `cache`.
3. Observe that `formula/evaluation.js`/`formula/validation.js` re-invoke `nearley.Parser(...).feed(formula)` on every trigger (cache miss every time), increasing validation CPU time per unit across the network, versus a baseline where formulas are reused and hit cache. [5](#0-4) [1](#0-0)

### Citations

**File:** formula/evaluation.js (L104-121)
```javascript
	var parser = {};
	if(cache[formula]){
		parser.results = cache[formula];
	}else {
		try {
			parser = new nearley.Parser(nearley.Grammar.fromCompiled(grammar));
			parser.feed(formula);
			formulasInCache.push(formula);
			cache[formula] = parser.results;
			if (formulasInCache.length > cacheLimit) {
				var f = formulasInCache.shift();
				delete cache[f];
			}
		}catch (e) {
			console.log('exception from parser', e);
			return callback('parse failed: '+e, null);
		}
	}
```

**File:** formula/common.js (L1-7)
```javascript
var Decimal = require('decimal.js');
var constants = require('../constants');
var ValidationUtils = require("../validation_utils.js");

var cacheLimit = 100;
var formulasInCache = [];
var cache = {};
```

**File:** formula/validation.js (L249-262)
```javascript
	var parser = {};
	try {
		if(cache[formula]){
			parser.results = cache[formula];
		}else {
			parser = new nearley.Parser(nearley.Grammar.fromCompiled(grammar));
			parser.feed(formula);
			if(formulasInCache.length > cacheLimit){
				var f = formulasInCache.shift();
				delete cache[f];
			}
			formulasInCache.push(formula);
			cache[formula] = parser.results;
		}
```

**File:** aa_composer.js (L618-654)
```javascript
	function replace(obj, name, path, locals, xpath, cb) {
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(replace, obj, name, path, locals, xpath, cb);
		locals = _.clone(locals);
		var value = obj[name];
		if (typeof name === 'string') {
			xpath += '/' + name;
			var f = getFormula(name);
			if (f !== null) {
				var opts = {
					conn: conn,
					formula: f,
					trigger: trigger,
					params: params,
					locals: _.clone(locals),
					stateVars: stateVars,
					responseVars: responseVars,
					objValidationState: objValidationState,
					address: address
				};
				return formulaParser.evaluate(opts, [], xpath, function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + f + " failed: "+err);
					delete obj[name];
					if (res === '')
						return cb(); // the key is just removed from the object
					if (typeof res !== 'string')
						return cb({message: "result of formula " + name + " is not a string: " + res, xpath});
					if (ValidationUtils.hasOwnProperty(obj, res))
						return cb({message: "duplicate key " + res + " calculated from " + name, xpath});
					if (getFormula(res) !== null)
						return cb({message: "calculated value of " + name + " looks like a formula again: " + res, xpath});
					assignField(obj, res, value);
					replace(obj, res, path, locals, xpath, cb);
				});
			}
```
