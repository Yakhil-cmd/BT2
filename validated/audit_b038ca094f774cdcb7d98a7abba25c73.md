## Analysis

The Compound report describes value that accrues to an address (unclaimed rewards) but is never reflected in the value/balance accounting the protocol relies on, causing an undervaluation with downstream fund-handling consequences. In `ocore` there is a directly analogous and stronger issue involving Autonomous Agent (AA) balance accounting: **headers-commission and witnessing earnings that get attributed to an AA address are never credited to `aa_balances`, and AAs are explicitly forbidden from constructing the input types needed to ever spend them**, permanently freezing those funds.

Relevant code:
- `aa_balances` is only ever populated/updated from the `outputs` table (payments), never from `headers_commission_outputs`/`witnessing_outputs`: [1](#0-0)  and the `balance[]`/`var[]` oscript operator reads the same `aa_balances`-derived state: [2](#0-1) .
- AA trigger processing (`updateInitialAABalances`/`updateFinalAABalances`) only tracks deltas from `trigger.outputs` and payment messages, never from commission tables: [3](#0-2) [4](#0-3) .
- Headers commission is distributed to whichever address authored the winning child unit, or to any address(es) an author designates via `earned_headers_commission_recipients` — this is not restricted to non-AA addresses: [5](#0-4)  and [6](#0-5) . AA response units are ordinary units authored by the AA's own address, so they participate in this selection like any other unit.
- Crucially, spending a `headers_commission`/`witnessing` type input is explicitly blocked for AAs: [7](#0-6) .

### Title
AA-attributed headers-commission/witnessing earnings are never credited to `aa_balances` and can never be spent, permanently freezing funds - (File: `aa_composer.js`, `storage.js`, `headers_commission.js`, `validation.js`)

### Summary
Any bytes routed to an AA address via headers commission (as the winning child-unit author, or via `earned_headers_commission_recipients`) or via paid witnessing land in the `headers_commission_outputs`/`witnessing_outputs` tables. These amounts are never added to the AA's `aa_balances` and can never be spent by the AA because AA units are explicitly barred from using `headers_commission`/`witnessing` input types. The bytes are permanently lost/frozen, and the AA's oscript logic (`balance[]`) never even sees them, so it cannot compensate.

### Finding Description
AA balance state (`aa_balances`, exposed to oscript via `balance[...]`) is populated exclusively from the `outputs` table representing payment messages: `updateInitialAABalances` seeds balances from `aa_balances`/trigger outputs, and `updateFinalAABalances` adjusts them only from consumed/produced payment outputs [8](#0-7) . The same is true when an AA is first defined: its opening balance is computed purely from the `outputs` table [1](#0-0) .

Separately, `headers_commission.js` distributes `headers_commission` bytes from every stable parent unit to whichever child unit wins (by author address, or by `earned_headers_commission_recipients` if declared) [5](#0-4) . Nothing restricts the recipient address from being an AA address: `validateHeadersCommissionRecipients` only validates share percentages and address format/sorting, not whether the address is an AA [6](#0-5) . An AA's own response units are ordinary units authored by the AA address and can legitimately be selected as the "best child" winner of a headers commission, or any unit author can simply put an AA address into `earned_headers_commission_recipients`. `paid_witnessing.js` similarly can route payload-commission earnings to any address acting as an MC witness.

Once such an output lands in `headers_commission_outputs`/`witnessing_outputs` for an AA address, it is invisible to `balance[]`/`var[]` reads (`readBalance` only looks at `aa_balances`) [2](#0-1) , and it can never be spent, because `validatePaymentInputsAndOutputs` explicitly rejects `headers_commission`/`witnessing` input types whenever `objValidationState.bAA` is true [7](#0-6) . Only a manually authored (non-AA) unit can construct such inputs, and AAs cannot author units outside of their deterministic trigger-response mechanism.

### Impact Explanation
This causes a real, permanent loss of funds: bytes credited to an AA address as headers commission or witnessing rewards can never be withdrawn or used by that AA, and the AA's own internal accounting (`balance[]`) never reflects them, so AA logic built around `balance[base]` (e.g., "send-all" logic, liquidity/market-maker AAs as in `test/samples/uniswap_like_market_maker.oscript`) will systematically under-report true holdings and permanently strand any commission bytes routed to it. This is a stronger analog of the original "undervalued TVL" issue — instead of merely undervaluing, the value becomes permanently unrecoverable, matching the "AA fund loss or freezing" impact category.

### Likelihood Explanation
This is reachable by any unprivileged unit poster with no special privileges: (1) an AA's own response units naturally compete for and can win headers commissions as part of ordinary DAG growth, and (2) any unit author can freely set `earned_headers_commission_recipients` to point at any known AA address, deliberately or accidentally diverting bytes there. No cooperation from the AA operator, witnesses, or special conditions are required.

### Recommendation
Either (a) disallow AA addresses from being headers-commission/witnessing recipients (reject at validation time when the recipient/winning-author address is a known AA address), or (b) allow AA-authored units to construct `headers_commission`/`witnessing` type inputs (removing/adjusting the `bAA` restriction in `validatePaymentInputsAndOutputs`) and integrate these amounts into `aa_balances` so `balance[]` reflects them and they become spendable by the AA's own trigger logic.

### Proof of Concept
1. Deploy an AA `X`.
2. Any user posts a unit `U1` whose parent is some unit `P` that also has `X`'s own (unrelated) response unit as a sibling child of `P`; if `X`'s response unit wins the deterministic best-child selection in `getWinnerInfo` [9](#0-8) , `P`'s `headers_commission` bytes are credited to address `X` in `headers_commission_outputs`.
   - Alternatively, any user simply authors a unit specifying `earned_headers_commission_recipients: [{address: X, earned_headers_commission_share: 100}]`, which passes validation per `validateHeadersCommissionRecipients` [6](#0-5) , directly routing their own commission to `X`.
3. Query `light/get_aa_balances` for `X` [10](#0-9)  or evaluate `balance[base]` inside `X` — the credited commission amount is absent.
4. Attempt to have `X` spend those bytes via any payment message; this is impossible because no unit authored by an AA can include a `headers_commission`/`witnessing` type input, per the explicit `bAA` check [7](#0-6) . The bytes are permanently stuck in `headers_commission_outputs`, unspendable by anyone.

### Citations

**File:** storage.js (L954-962)
```javascript
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
						params,
```

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```

**File:** aa_composer.js (L474-587)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
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
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
			}
		);
	}

	function updateFinalAABalances(arrConsumedOutputs, objUnit, cb) {
		if (trigger_opts.bAir)
			throw Error("updateFinalAABalances shouldn't be called with bAir");
		var assocDeltas = {};
		var arrNewAssets = [];
		arrConsumedOutputs.forEach(function (output) {
			if (!assocDeltas[output.asset])
				assocDeltas[output.asset] = 0;
			assocDeltas[output.asset] -= output.amount;
			// this might happen if there is another pending invocation of our AA that created the outputs we are spending now
			if (!objValidationState.assocBalances[address][output.asset])
				arrNewAssets.push(output.asset);
		});
		objUnit.messages.forEach(function (message) {
			if (message.app !== 'payment')
				return;
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address !== address)
					return;
				if (!assocDeltas[asset]) { // it can happen if the asset was issued by AA
					assocDeltas[asset] = 0;
					arrNewAssets.push(asset);
				}
				assocDeltas[asset] += output.amount;
			});
		});
		var arrQueries = [];
		if (arrNewAssets.length > 0) {
			var arrValues = arrNewAssets.map(function (asset) { return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", 0)"; });
			conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
		}
		for (var asset in assocDeltas) {
			if (assocDeltas[asset]) {
				conn.addQuery(arrQueries, "UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=?", [assocDeltas[asset], address, asset]);
				if (!objValidationState.assocBalances[address][asset])
					objValidationState.assocBalances[address][asset] = 0;
				objValidationState.assocBalances[address][asset] += assocDeltas[asset];
			}
		}
		if (assocDeltas.base)
			byte_balance += assocDeltas.base;
		async.series(arrQueries, cb);
	}
```

**File:** headers_commission.js (L12-67)
```javascript
function calcHeadersCommissions(conn, onDone){
	// we don't require neither source nor recipient to be majority witnessed -- we don't want to return many times to the same MC index.
	console.log("will calc h-comm");
	if (max_spendable_mci === null) // first calc after restart only
		return initMaxSpendableMci(conn, function(){ calcHeadersCommissions(conn, onDone); });
	
	// max_spendable_mci is old, it was last updated after previous calc
	var since_mc_index = max_spendable_mci;
		
	async.series([
		function(cb){
			if (conf.storage === 'mysql'){
				var best_child_sql = "SELECT unit \n\
					FROM parenthoods \n\
					JOIN units AS alt_child_units ON parenthoods.child_unit=alt_child_units.unit \n\
					WHERE parent_unit=punits.unit AND alt_child_units.main_chain_index-punits.main_chain_index<=1 AND +alt_child_units.sequence='good' \n\
					ORDER BY SHA1(CONCAT(alt_child_units.unit, next_mc_units.unit)) \n\
					LIMIT 1";
				// headers commissions to single unit author
				conn.query(
					"INSERT INTO headers_commission_contributions (unit, address, amount) \n\
					SELECT punits.unit, address, punits.headers_commission AS hc \n\
					FROM units AS chunits \n\
					JOIN unit_authors USING(unit) \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
					WHERE chunits.is_stable=1 \n\
						AND +chunits.sequence='good' \n\
						AND punits.main_chain_index>? \n\
						AND chunits.main_chain_index-punits.main_chain_index<=1 \n\
						AND +punits.sequence='good' \n\
						AND punits.is_stable=1 \n\
						AND next_mc_units.is_stable=1 \n\
						AND chunits.unit=( "+best_child_sql+" ) \n\
						AND (SELECT COUNT(*) FROM unit_authors WHERE unit=chunits.unit)=1 \n\
						AND (SELECT COUNT(*) FROM earned_headers_commission_recipients WHERE unit=chunits.unit)=0 \n\
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
					FROM units AS chunits \n\
					JOIN earned_headers_commission_recipients USING(unit) \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
					WHERE chunits.is_stable=1 \n\
						AND +chunits.sequence='good' \n\
						AND punits.main_chain_index>? \n\
						AND chunits.main_chain_index-punits.main_chain_index<=1 \n\
						AND +punits.sequence='good' \n\
						AND punits.is_stable=1 \n\
						AND next_mc_units.is_stable=1 \n\
						AND chunits.unit=( "+best_child_sql+" )", 
					[since_mc_index, since_mc_index], 
					function(){ cb(); }
				);
```

**File:** headers_commission.js (L249-259)
```javascript
function getWinnerInfo(arrChildren){
	if (arrChildren.length === 1)
		return arrChildren[0];
	if (arrChildren.length === 0)
		throw Error("no children for hc");
	arrChildren.forEach(function(child){
		child.hash = crypto.createHash("sha1").update(child.child_unit + child.next_mc_unit, "utf8").digest("hex");
	});
	arrChildren.sort(function(a, b){ return ((a.hash < b.hash) ? -1 : 1); });
	return arrChildren[0];
}
```

**File:** validation.js (L1101-1126)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknown fields in recipient");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
	cb();
}
```

**File:** validation.js (L2529-2532)
```javascript
				case "headers_commission":
				case "witnessing":
					if (objValidationState.bAA)
						return cb(type+" in AA");
```

**File:** network.js (L3998-4006)
```javascript
		case 'light/get_aa_balances':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/get_aa_balances");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
			storage.readAABalances(db, params.address, function(assocBalances) {
				sendResponse(ws, tag, { balances: assocBalances });
			});
			break;
```
