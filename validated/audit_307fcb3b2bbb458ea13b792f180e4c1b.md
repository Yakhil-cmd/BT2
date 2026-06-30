Looking at the Aurora Engine codebase for an analog to the "contradictory access control conditions making a critical admin function permanently unusable" vulnerability class.

I examined all admin functions in `engine/src/contract_methods/admin.rs` for contradictory pre-check conditions within the same function:

**`start_hashchain`** (lines 426–464):
- `require_paused(&state)?` — requires `is_paused == true`
- `require_key_manager_only(...)` — requires key manager is set and caller matches

**`set_key_manager`** (lines 275–296):
- `require_running(&state)?` — requires `is_paused == false`

**`pause_contract`** (lines 251–260):
- `require_owner_only` + `require_running` — not contradictory internally

**`resume_contract`** (lines 263–272):
- `require_owner_only` + `require_paused` — not contradictory internally

**`set_owner`** (lines 104–121):
- `require_running` + `require_owner_only` + `ERR_SAME_OWNER` guard — not contradictory

No function in the Aurora Engine production scope contains two mutually exclusive conditions **within the same function** that would cause it to always revert. The closest structural tension — `start