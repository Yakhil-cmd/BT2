### Title
Unbounded growth of `aa_balances` rows per AA address enables denial-of-service against every future trigger to that AA - ([File: aa_composer.js])

### Summary
`updateInitialAABalances` in `aa_composer.js` loads every distinct `(address, asset)` balance row ever recorded for an autonomous agent and iterates over all of them on **every single trigger** sent to that AA, with no cap on how many distinct assets an address's balance table may contain. Any unprivileged unit poster can permissionlessly pay dust amounts of arbitrarily many distinct assets to a target AA, permanently growing the number of rows the AA's balance query and its `rows.forEach` loop must process, degrading (and eventually threatening to break) validation/execution of *every future trigger* sent to that AA by anyone — directly mirroring the OpenQ "unbounded whitelisted token iteration causes OOG on claim" bug class.

### Finding Description
When any trigger (a payment message from any unprivileged address) targets an AA, `handleTrigger` calls `updateInitialAABalances`, which does: [1](#0-0) 

This runs `SELECT asset, balance FROM aa_balances WHERE address=?` and then `rows.forEach(...)` over **all** distinct assets ever credited to the AA's address — there is no limit on the number of distinct assets that can accumulate in `aa_balances` for a single address.

The only assets check that exists is `validateAATriggerObject`, which limits the assets *carried in a single trigger unit* to `MAX_MESSAGES_PER_UNIT` (128): [2](#0-1) 

That check bounds a single unit's payload, but nothing prevents an attacker from sending many separate trigger units over time, each carrying one or a few previously-unseen assets with dust amounts, to the same AA address. Because base-asset payments must exceed `bounce_fees.base` to avoid an instant no-op bounce, but the "insert new asset balance row" branch executes unconditionally for *any* new asset present in `trigger.outputs` regardless of amount: [3](#0-2) 

each such transaction permanently inserts a new row into `aa_balances` for that address, at the cost of only asset-issuance/transfer fees (comparable in spirit to OpenQ's "whitelisted token" deposit, since ocore has no protocol-level whitelist and *any* valid asset unit can be used). The only real limiting factor is that issuing a brand-new asset still costs a whole unit; however, an attacker only needs to issue N assets once and can then reuse them indefinitely to target multiple AAs, and the cost asymmetry (attacker pays once per asset; every future caller of the victim AA pays the accumulated iteration overhead) is exactly the imbalance flagged in the original report.

### Impact Explanation
Every legitimate future trigger to the targeted AA — sent by unrelated, honest users — must pay the cost of the growing `SELECT ... WHERE address=?` query and the `forEach` loop over all historical asset balances, even though the trigger itself may only involve the base asset. Since this happens inside consensus-critical AA response computation (which must be deterministically reproduced by every full node to determine AA responses, balances, and resulting unit content), an attacker can:
- Progressively degrade performance/availability of a specific AA for all its users (denial of service against the AA), and
- In the worst case (very large numbers of accumulated distinct-asset rows), cause disproportionate computation time relative to `MAX_COMPLEXITY`/fee-metered formula evaluation elsewhere in the AA engine, even though this particular loop is not formula-metered at all, since it runs in the JS host layer prior to formula evaluation and is not gated by any anti-spam or fee-based cap.

This satisfies the "AA fund loss/freezing" and "node unable to process/confirm" impact categories, since it can make an AA increasingly expensive/impossible for third parties to interact with, at attacker cost that does not scale with victim cost.

### Likelihood Explanation
Likelihood is high in principle: no privileged role is required, any address can issue a new asset unit (see `validateAssetDefinition`, `validatePayment`) and send a dust amount of it to a target AA address in a normal payment message that becomes a trigger. There is no fee, cap, or check preventing accumulation of arbitrarily many distinct-asset balance rows per AA address in `aa_balances`. The practical severity is bounded by real-world unit cost (each new asset costs a full unit + issuance fee), so this is a resource-exhaustion/griefing vector rather than an instant, cheap attack, but it is unbounded over time given persistent attacker investment, matching the "any bad actor can add dust amount of many tokens" pattern from the source report.

### Recommendation
Introduce an explicit cap on the number of distinct assets that may be tracked in `aa_balances` for a single AA address (e.g., reject/ignore payments of a new asset to an AA once a configured `MAX_ASSETS_PER_AA_BALANCE` is reached, or require the AA definition itself to opt in to handling additional assets). Alternatively, charge a per-new-asset storage/anti-spam fee at the time a previously-unseen asset balance row is created for an AA (analogous to the existing `storage_size` byte-balance accounting), so the attacker who inflates `aa_balances` pays proportionally to the DoS cost imposed on future callers, rather than externalizing that cost onto every legitimate user of the AA.

### Proof of Concept
1. Attacker issues `N` distinct new assets (`asset_1 … asset_N`), each via a standard `asset` definition message plus an initial `payment` (issue) message — no special privilege required.
2. For each asset, attacker sends a payment message with a dust output (e.g., 1 unit of the asset) to a target AA address `X`. Each such payment is a valid trigger; per `updateInitialAABalances`, a new row is inserted into `aa_balances` for `(X, asset_i)`.
3. Repeat step 2 for arbitrarily many assets over time — there is no cap enforced in `updateInitialAABalances` (`aa_composer.js` lines 491–541) on the total number of distinct-asset rows accumulated for address `X`.
4. Any subsequent, unrelated trigger sent to AA `X` by a legitimate user now causes `SELECT asset, balance FROM aa_balances WHERE address=?` to return and iterate over all `N+` rows in `rows.forEach`, imposing ever-growing per-trigger overhead on every future caller of AA `X`, unbounded by protocol limits.

I could not find any code path that caps or fee-meters the size of `aa_balances` per address, nor any consensus-level rejection of assets sent to an AA beyond the per-unit `MAX_MESSAGES_PER_UNIT` check in `validateAATriggerObject`; this gap is the root cause enabling the analog of the OpenQ finding.

### Citations

**File:** aa_composer.js (L244-246)
```javascript
	var arrAssets = Object.keys(trigger.outputs).filter(function(asset) {return asset !== 'base'});
	if (arrAssets.length >= constants.MAX_MESSAGES_PER_UNIT)
		return handle("too many assets");
```

**File:** aa_composer.js (L491-514)
```javascript
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
```

**File:** aa_composer.js (L515-524)
```javascript
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
```
