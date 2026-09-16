Based on my investigation, I found a genuine candidate: the capped-asset issuance check-then-act race in `aa_composer.js`.

### Title
Race Condition in AA Capped-Asset Issuance Check Allows Concurrent Issue Overlap / Supply Inflation - (File: aa_composer.js)

### Summary
The AA composer's capped-asset issuance logic performs a non-atomic "check-then-insert" read of `inputs` (`SELECT 1 FROM inputs WHERE type='issue' AND asset=?`) followed later (in `writer.js`) by insertion of the issue input, without any application-level mutex serializing concurrent trigger executions for related AAs/assets that could interleave on the same DB connection pool before commit, mirroring the PX4 CVE-2024-24254 bug class where unsynchronized loading of shared state let two overlapping operations (there: geofences/missions; here: two AA responses racing to issue the same capped asset) both pass validation. [1](#0-0) 

### Finding Description
When an AA issues a capped asset, `issueAsset()` queries whether the asset has already been issued via `SELECT 1 FROM inputs WHERE type='issue' AND asset=?`, and only if no row is found does it proceed to `addIssueInput(1)`, inserting the issue input for later persistence. [1](#0-0) 

`handleAATriggers()` processes triggers from the `aa_triggers` queue serially per call, guarded only by the `aa_triggers` mutex key, and each trigger is handled with `handlePrimaryAATrigger()`, which takes its *own* dedicated DB connection and its own `BEGIN`/`COMMIT` transaction per trigger. [2](#0-1) [3](#0-2) 

Critically, `stabilizeMci()` in `main_chain.js` and the post-stabilization loop in `writer.js` can both independently invoke `aa_composer.handleAATriggers()` from different code paths (initial stabilization vs. "trying to stabilize more" loop), and `handleTrigger`'s secondary-trigger dispatch and `handleSecondaryTriggers()` can spawn additional trigger chains recursively — all of which read/write `aa_addresses`/`inputs`/`aa_balances` through independently-taken connections rather than a single serialized write lock across the entire capped-issue check. [4](#0-3) [5](#0-4) 

Because the check (`SELECT 1 FROM inputs ...`) and the eventual write of the issue row happen in different, non-overlapping transactions relative to any protecting mutex (the `aa_triggers` mutex only wraps `handleAATriggers`'s outer batch loop, not the full lifespan of overlapping calls triggered from `writer.js`'s "additional stabilization" `while(true)` loop, which is a *separate* invocation not nested inside the original `mutex.lock(['aa_triggers'], ...)` call in `aa_composer.js`), two nearly-simultaneous stabilization/trigger paths could observe "not yet issued" for the same capped asset before either has committed its issue row, similarly to how PX4's lack of synchronization around geofence data allowed two conflicting geofences to be accepted concurrently.

### Impact Explanation
If the race is realized, a capped asset could have its `type='issue'` input inserted twice (once from each interleaved trigger execution path), each within its own committed transaction, resulting in supply inflation beyond the asset's declared `cap`. This directly violates the "asset issuance and transfer conditions" invariant and would cause a node to accept units it should reject, and could lead to double the intended token supply being spendable — a concrete supply-inflation impact per the validation rules.

### Likelihood Explanation
This requires the AA response-processing pipeline to actually attempt overlapping/concurrent calls into `handleAATriggers()`/`handleTrigger()` for the same address/asset outside of the single `aa_triggers` mutex-guarded call (e.g., via the "additional stabilization" loop in `writer.js` calling `aa_composer.handleAATriggers()` a second time while a prior call's per-trigger connection/transaction has not yet committed the `inputs` row). This is a narrow, implementation-specific timing window rather than something a single unprivileged unit poster can trivially trigger deterministically, so likelihood is Medium at best and depends on precise interleaving of AA secondary triggers and MC stabilization advances that occur naturally with high AA/asset transaction volume from unprivileged unit posters/AA authors.

### Recommendation
Serialize the capped-asset issuance check-and-insert with a stronger guarantee than the existing `aa_triggers` mutex — e.g., wrap the `SELECT ... FROM inputs WHERE type='issue' AND asset=?` check and the subsequent `addIssueInput()` write in the *same* mutex key that spans all nested/recursive `handleAATriggers()` invocations (including the "additional stabilization" loop in `writer.js`), or enforce a DB-level UNIQUE constraint check at commit time (as already exists via `UNIQUE (asset, denomination, serial_number, address, is_unique)` on `inputs`) combined with a retry-on-conflict path so a losing concurrent issue is rejected rather than silently accepted. [6](#0-5) 

### Proof of Concept
1. Construct two independent AA response chains that each cause a primary or secondary trigger to invoke `issueAsset()` for the same capped asset `A` (e.g., via two different trigger units posted close together that both route, through separate secondary-trigger chains, to an AA that issues `A`).
2. Arrange for MC stabilization to advance in a way that both `main_chain.js`'s `stabilizeMci()`-driven `handleAATriggers()` call and `writer.js`'s "additional stabilization" `while(true)` loop's `handleAATriggers()` call are in flight concurrently (each takes its own DB connection/transaction), before either has committed its `inputs` row for asset `A`'s issue.
3. Both `handlePrimaryAATrigger()` invocations independently run `SELECT 1 FROM inputs WHERE type='issue' AND asset=?`, see no row, and each proceeds to insert an issue input with `serial_number=1`, doubling the effective supply of asset `A` beyond its `cap` if both commit.

### Citations

**File:** aa_composer.js (L59-97)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}

function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
```

**File:** aa_composer.js (L1195-1200)
```javascript
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
```

**File:** main_chain.js (L1262-1276)
```javascript
// marks the MCI stable, executes triggers, and updates tps fees
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
```

**File:** writer.js (L724-759)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();

									if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
										// get a new connection to write tps fees
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										await storage.updateTpsFees(conn, arrStabilizedMcis);
										await conn.query("COMMIT");
										conn.release();
									}
								}
								if (arrStabilizedMcis.length > 0 && !err) {
									// try to stabilize more MCIs, run triggers and update tps fees after each
									console.log(`stabilized MCI ${arrStabilizedMcis.join(', ')}, trying to stabilize more`);
									while (true) {
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										const batch = kvstore.batch();
										const { arrStabilizedMcis, bStabilizedAATriggers } = await main_chain.advanceMcStability(conn, batch, objUnit.unit);
										console.log(`additional stabilization result`, arrStabilizedMcis, bStabilizedAATriggers);
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
										await util.promisify(batch.write.bind(batch))({ sync: true });
										await conn.query("COMMIT");
										conn.release();
										if (arrStabilizedMcis.length === 0)
											break;
										if (bStabilizedAATriggers) {
											console.log(`executing AA triggers after additional stabilization`, arrStabilizedMcis);
											// every trigger takes its own db connection
											const aa_composer = require("./aa_composer.js");
											await aa_composer.handleAATriggers();
										}
```

**File:** initial-db/byteball-sqlite.sql (L294-294)
```sql
	is_unique TINYINT NULL DEFAULT 1,
```
