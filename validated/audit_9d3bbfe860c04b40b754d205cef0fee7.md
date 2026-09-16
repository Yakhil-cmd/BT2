I have sufficient evidence to answer now.

### Title
Missing built-in access control on AA state-variable initialization allows front-running of one-time setup logic (asset creation, ownership assignment, config admin) - ([File: things_registry_and_marketplace.oscript / 51_attack_game.oscript / aa_composer.js])

### Summary
Autonomous Agents (AAs) in ocore are the closest analog to on-chain "programs/contracts" referenced in the external report. An AA's persistent configuration is stored in generic key/value `state vars` that are written via the `state_var_assignment` opcode in the oscript formula engine [1](#0-0) . The core engine (`aa_composer.js`, `formula/evaluation.js`) provides no built-in "only-once" or "only-owner" semantics for these vars: any account can send a trigger unit to an AA, and if the AA's oscript performs an unconditional state-var write on first-use paths (e.g. creating an asset, assigning an "owner"/"admin"), the very first attacker to trigger that branch permanently wins that state — exactly the same "insecure initializer" bug class as the reported Solana `init_*` functions with no deployer/authority check.

### Finding Description
An AA is deployed with a fixed definition (oscript) and is triggered by any unprivileged unit poster sending a payment/data message to its address, exactly like any other unprivileged AA trigger sender in scope. State vars set inside `messages[].state` blocks are the AA's only persistent storage and are globally writable by whichever trigger reaches that code path first [2](#0-1) . The engine enforces no ownership check on `var[name] = value`; the *only* protection against a race is defense-in-depth code the AA author must write, i.e. explicit guards such as `if (var['owner']) bounce(...)` before performing a one-time assignment. This pattern is used pervasively in the very AA samples shipped with the repo to protect thing/asset/team "registration" style flows:
- Asset creation guarded by `!var['yes_asset']` / `!var['no_asset']` [3](#0-2) 
- Team asset creation guarded by `if (var['team_...'+trigger.address+'_asset']) bounce('you already have a team')` [4](#0-3) 
- Thing "registration" (ownership assignment) guarded by `if (var['owner_'||$id]) bounce('thing already registered')` [5](#0-4) 

These guards are exactly analogous to the report's recommendation to "verify the deployer or other known address" before initialization — but ocore's oscript engine does not enforce them; they are 100% optional, author-supplied checks. If an AA author omits the `!var['x']` (or equivalent) guard on a first-use/"claim" branch — which is easy to overlook, especially for branches meant to be triggered once by a specific deployer/admin address (e.g. setting a fee recipient, treasury address, or admin-only parameter) — any unprivileged party can send the qualifying trigger first and permanently set the sensitive state var to their own address, because `state_var_assignment` and `aa_composer.js`'s `handleTrigger`/formula `replace` logic apply the write unconditionally as soon as the branch's `if:` condition and internal `init:` checks (whatever the author wrote) pass [6](#0-5) .

### Impact Explanation
Because state vars can hold anything from asset identifiers to addresses used later in "address definition"/authorization-style checks (`var['admin']`, `var['owner']`, `var[$destination_aa]`), a race-won initialization lets the attacker seize control of an AA's privileged role. Downstream messages (payments, asset issuance, or definitions) that trust that state var (e.g. only allow "owner" to withdraw funds, or that a specific address may configure fees) would then serve the attacker instead of the legitimate deployer, leading to AA fund loss/misdirection or unauthorized asset control — matching the "AA fund loss" and "supply inflation/asset control" impact classes in scope. Because this affects arbitrary user-deployed AAs on the live network, severity is Medium, matching the original report's Medium/Medium.

### Likelihood Explanation
Any user can post a trigger unit to an AA the moment its definition becomes visible on the DAG (often before the intended deployer/admin's own configuration unit reaches stability), so exploitation only requires normal unit-posting rights and no special privilege — the same "single posted unit/trigger" reachability required by scope rules. The likelihood of a given AA lacking the guard depends entirely on the author, but the platform does nothing to prevent or even warn about this pattern, making it a systemic footgun rather than a one-off coding mistake, and the shipped sample AAs demonstrate that this is a widely necessary, easily-forgotten manual mitigation.

### Recommendation
Provide native primitives in the AA/oscript engine to reduce this class of bugs, e.g.:
- A documented/linted "constructor-once" semantics or a validator warning (in `aa_validation.js`) when a branch writes to a state var that is never read/guarded elsewhere in the same or a preceding branch.
- Formalize a "definer"/"deployer" concept for AAs (analogous to Solana's upgrade authority) that oscript can reference directly (similar to `trigger.address`), so authors can trivially gate first-time configuration to a specific address without hand-rolling `!var[...]` checks.
- Add to the AA documentation/oscript IDE tooling an explicit lint rule flagging unconditional state-var writes on trigger-controlled branches that set values later used as authorization checks.

### Proof of Concept
1. Deploy an AA whose oscript contains a case such as:
```
{
  if: `{trigger.data.set_admin}`,
  messages: [{ app: 'state', state: `{ var['admin'] = trigger.address; }` }]
}
```
without the `!var['admin']` guard (the pattern shown correctly in `things_registry_and_marketplace.oscript`/`51_attack_game.oscript` for analogous fields).
2. The deployer intends to send their own `{data:{set_admin:true}}` trigger right after deployment to become admin.
3. An attacker monitoring new AA definitions (`aa_definition_saved` event, emitted as soon as the AA's defining unit is seen [7](#0-6) ) posts their own `{data:{set_admin:true}}` trigger first.
4. `aa_composer.js`/`formula/evaluation.js` process the attacker's trigger, executing `var['admin'] = trigger.address` unconditionally and storing the attacker's address as `admin` [8](#0-7) .
5. Any later branch that checks `trigger.address == var['admin']` for privileged actions (fund withdrawal, fee configuration, etc.) now authorizes the attacker instead of the legitimate deployer.

### Citations

**File:** formula/evaluation.js (L1308-1362)
```javascript
			case 'state_var_assignment':
				if (!bStateVarAssignmentAllowed)
					return setFatalError("state var assignment not allowed here", { arr }, false, cb);
				var var_name_or_expr = arr[1];
				var rhs = arr[2];
				var assignment_op = arr[3];
				evaluate(var_name_or_expr, function (var_name) {
					if (fatal_error)
						return cb(false);
					if (typeof var_name !== 'string')
						return setFatalError("assignment: state var name must be string, " + var_name_or_expr + " evaluated to " + JSON.stringify(var_name) + ` (${typeof var_name})`, { arr }, false, cb);
					evaluate(rhs, function (res) {
						if (fatal_error)
							return cb(false);
						if (!isValidValue(res) && !(res instanceof wrappedObject))
							return setFatalError("evaluation of rhs " + rhs + " in state var assignment failed: " + JSON.stringify(res), { arr }, false, cb);
						if (Decimal.isDecimal(res))
							res = toDoubleRange(res);
						// state vars can store strings, decimals, objects, and booleans but booleans are treated specially when persisting to the db: true is converted to 1, false deletes the var
						if (res instanceof wrappedObject) {
							if (mci < constants.aa2UpgradeMci)
								res = true;
							else {
								if (assignment_op !== '=' && assignment_op !== '||=')
									return setFatalError(assignment_op + " not supported for object vars", { arr }, false, cb);
								try {
									var json = string_utils.getJsonSourceString(res.obj, true);
								}
								catch (e) {
									return setFatalError("stringify failed: " + e, { arr }, false, cb);
								}
								if (json.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
									return setFatalError("state var value too long when in json: " + json, { arr }, false, cb);
								if (isTooBigObj(res.obj))
									return setFatalError("rhs of state var assignment is too big", { arr }, false, cb);
								res = new wrappedObject(string_utils.cloneDeep(res.obj)); // make a copy
							}
						}
						if (var_name.length > constants.MAX_STATE_VAR_NAME_LENGTH)
							return setFatalError("state var name too long: " + var_name, { arr }, false, cb);
						if (!var_name.isWellFormed())
							return setFatalError("state var name not well formed: " + var_name, { arr }, false, cb);
						if (typeof res === 'string' && !res.isWellFormed())
							return setFatalError("state var value not well formed: " + res, { arr }, false, cb);
					//	if (typeof res === 'boolean')
					//		res = res ? dec1 : dec0;
						if (!stateVars[address])
							stateVars[address] = {};
					//	console.log('---- assignment_op', assignment_op)
						readVar(address, var_name, function (value) {
							if (assignment_op === "=") {
								if (typeof res === 'string' && res.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
									return setFatalError("state var value too long: " + res, { arr }, false, cb);
								stateVars[address][var_name].value = res;
								stateVars[address][var_name].updated = true;
```

**File:** test/samples/option_contract.oscript (L4-11)
```text
			{ // define YES and NO assets
				if: `{
					$define_yes = trigger.data.define_yes AND !var['yes_asset'];
					$define_no = trigger.data.define_no AND !var['no_asset'];
					if ($define_yes AND $define_no)
						bounce("can't define both assets at the same time");
					$define_yes OR $define_no
				}`,
```

**File:** test/samples/51_attack_game.oscript (L25-32)
```text
			{ // create a new team; any excess amount is sent back
				if: `{trigger.data.create_team AND !$bFinished}`,
				init: `{
					if (var['team_' || trigger.address || '_asset'])
						bounce('you already have a team');
					if (trigger.output[[asset=base]] < $team_creation_fee)
						bounce('not enough to pay for team creation');
				}`,
```

**File:** test/samples/things_registry_and_marketplace.oscript (L22-32)
```text
			{ // register a new thing and optionally put it on sale
				if: `{trigger.data.register AND $id}`,
				init: `{
					if (var['owner_' || $id])
						bounce('thing ' || $id || ' already registered');
					if (trigger.data.sell){
						$price = trigger.data.price;
						if (!$price || !($price > 0) || round($price) != $price)
							bounce('please set a positive integer price');
					}
				}`,
```

**File:** aa_composer.js (L617-618)
```javascript
	// note that app=definition is also replaced using the current trigger and vars, its code has to generate "{}"-formulas in order to be dynamic
	function replace(obj, name, path, locals, xpath, cb) {
```

**File:** storage.js (L967-971)
```javascript
									// can emit again if bAlreadyPostedByUnconfirmedAA, that's ok, the watchers will learn that the AA became now available to non-AAs
									if (!bDryRun)
										process.nextTick(function () { // don't call it synchronously with event emitter
											eventBus.emit("aa_definition_saved", payload, unit);
										});
```
