## Title
AA pool participants can manipulate their unit's `level` to front-run loss-realizing triggers within the same MCI and exit before losses are socialized - (File: aa_composer.js, main_chain.js, writer.js)

### Summary
Autonomous Agent (AA) triggers that land in the same main-chain index (MCI) are executed in a fully deterministic order based on the triggering unit's `level` (and, as tie-break, unit hash), not on wall-clock arrival. Because a unit's `level` is simply `max(level of chosen parents) + 1`, and the parents are freely chosen by the composer at broadcast time, a user who anticipates that another pending unit will trigger a loss-realizing state change in a shared-pool AA (e.g. a market-maker/vault/lending-style AA that distributes pro-rata shares of `balance[asset]`) can deliberately pick shallow parents to keep their own `level` lower than the loss-causing unit's level while both land in the same MCI. Their withdrawal/divest trigger then executes first, letting them extract their share of the pool at the pre-loss valuation and pushing the loss onto the remaining participants — the same effect as the StakedToken `accrue()` front-run described in the external report, but achieved via level manipulation instead of transaction-pool front-running.

### Finding Description
AA trigger execution order for a stabilized MCI is deterministic and explicitly documented as such: [1](#0-0) 

```
"SELECT DISTINCT address, definition, units.unit, units.level ...
 ORDER BY units.level, units.unit, address", // deterministic order
```

and when triggers are dequeued for execution: [2](#0-1) 

```
"SELECT aa_triggers.mci, aa_triggers.unit, address, definition ...
ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
```

Both orderings key primarily on `level`. `level` is computed purely from the unit's chosen parents: [3](#0-2) 

```
function updateLevel(cb){
    ...
    determineMaxLevel(function(max_level){
        ...
        objNewUnitProps.level = max_level + 1;
        ...
    });
}
```

The parent set is selected by the wallet/composer when building a new unit (`pickParentUnitsAndLastBall` / `parent_composer.js`), so the author of a unit has direct control over the level assigned to it, within the constraints of witnessed-level/stability rules. A user who is watching the unstable DAG (which is fully visible, unlike a private mempool) can see an incoming unit that is about to trigger a value-destroying AA state change (e.g., an oracle price update, a large trade that moves an AMM price, or any state transition analogous to `applyLosses`/`accrue` in the report) before it stabilizes. By choosing older/shallower parents for their own withdrawal trigger, they can ensure their unit's `level` is lower than the loss-causing unit's `level`, so that when both land in the same MCI, `handleAATriggers`/`markMcIndexStable` process their withdrawal first — exactly mirroring the "frontrun `accrue`, redeem right before losses are applied" pattern from the report.

A concrete AA shape vulnerable to this is any pool-share design like the sample `uniswap_like_market_maker.oscript`, where "divest MM shares" pays out `investor_share * balance[asset]`/`balance[base]` computed at execution time: [4](#0-3) 

If a subsequent (but same-MCI) trigger would otherwise reduce `balance[$asset]`/`balance[base]` (e.g., a bad trade, a liquidation, or a price/data-feed-driven write-down implemented in a similar or more complex AA), a participant who controls their own unit's level can guarantee their "divest" trigger executes before the loss-causing trigger, receiving the pre-loss valuation and leaving remaining share-holders to absorb the loss.

### Impact Explanation
This allows a participant in a shared-value AA (pool, vault, insurance-style, lending-style, or synthetic-asset AA) to consistently avoid losses that are meant to be shared pro-rata across all holders, by exploiting a mechanism (`level`-based deterministic trigger ordering) that is fully attacker-controllable at unit-composition time rather than a neutral/random ordering. This causes an unfair, avoidable transfer of loss to the remaining holders — i.e., AA fund loss for legitimate remaining participants, and unauthorized economic advantage for the attacker who can select their unit's DAG position. It is a systemic design property, not confined to a single AA, so it affects every pool/vault-like AA built on top of this trigger-ordering guarantee.

### Likelihood Explanation
Likelihood is high for any actor running a full/light node who monitors the unstable DAG: unstable units and their messages (including oracle data feeds and payment triggers) are publicly visible before stabilization via `storage.assocUnstableMessages`/`assocUnstableUnits`, and constructing a unit with specific (older) parents is a normal composer operation, not requiring any special privilege — the same capability every wallet already uses via `parent_composer.js`/`composeJoint`. No collusion with witnesses, hubs, or other nodes is required.

### Recommendation
For AAs that must fairly share losses across participants, do not rely on the DAG's `level`-based trigger ordering as an unpredictable/fair sequencing mechanism. Practical mitigations at the AA-design level include: (1) applying a delay/cooldown (minimum holding or unstaking period) before allowing redemption after a loss-relevant event is recorded in state, analogous to the fix adopted by InfiniFi; (2) batching/netting loss realization and withdrawals that fall within the same MCI, e.g., by making the "loss" state update retroactively apply to any withdrawal recorded in the same MCI, rather than depending on execution order; (3) recording an oracle/loss-event timestamp and having the pool AA use the worst-case (already known) price/loss for any redemption whose trigger unit's `last_ball_mci` is not strictly before the mci at which the loss was posted.

### Proof of Concept
1. Deploy a pool AA (e.g., `uniswap_like_market_maker.oscript`-style) where withdrawal pays `investor_share * balance[asset]` computed at trigger-execution time.
2. Attacker holds pool shares and watches the DAG; attacker observes an unstable unit U (not yet part of a stable MCI) that will, once processed, trigger a large loss to the pool (e.g., an oracle data-feed update or a large adverse trade) once its MCI stabilizes.
3. Attacker composes a "divest" trigger unit W choosing parent units with a `level` strictly lower than U's expected `level`, ensuring `level(W) < level(U)`.
4. Both U and W stabilize within the same MCI; per `main_chain.js`/`aa_composer.js` deterministic ordering (`ORDER BY ..., level, ...`), W's trigger executes and pays out the attacker's shares at the pre-loss balance, before U's loss-causing trigger executes and reduces `balance[asset]`/`balance[base]` for the remaining holders. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** main_chain.js (L1691-1706)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```

**File:** aa_composer.js (L59-69)
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
```

**File:** writer.js (L451-484)
```javascript
		function determineMaxLevel(handleMaxLevel){
			var max_level = 0;
			async.each(
				objUnit.parent_units, 
				function(parent_unit, cb){
					storage.readStaticUnitProps(conn, parent_unit, function(props){
						if (props.level > max_level)
							max_level = props.level;
						cb();
					});
				},
				function(){
					handleMaxLevel(max_level);
				}
			);
		}
		
		function updateLevel(cb){
			if (bGenesis)
				return cb();
			conn.cquery("SELECT MAX(level) AS max_level FROM units WHERE unit IN(?)", [objUnit.parent_units], function(rows){
				if (!conf.bFaster && rows.length !== 1)
					throw Error("not a single max level?");
				determineMaxLevel(function(max_level){
					if (conf.bFaster)
						rows = [{max_level: max_level}]
					if (max_level !== rows[0].max_level)
						throwError("different max level, sql: "+rows[0].max_level+", props: "+max_level);
					objNewUnitProps.level = max_level + 1;
					conn.query("UPDATE units SET level=? WHERE unit=?", [rows[0].max_level + 1, objUnit.unit], function(){
						cb();
					});
				});
			});
```

**File:** test/samples/uniswap_like_market_maker.oscript (L67-100)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];
						}`
					},
				]
```
