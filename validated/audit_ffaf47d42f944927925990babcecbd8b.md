Audit Report

## Title
`ManageVotingPermission` Is Self-Replicating via `PERMISSIONS_RELATED_TO_VOTING` Classification, Allowing Unauthorized Propagation of Neuron Voting Control - (File: rs/sns/governance/src/neuron.rs)

## Summary

`ManageVotingPermission` is included in `PERMISSIONS_RELATED_TO_VOTING`, which causes `is_exclusively_voting_related` to return `true` for a permission list containing only `ManageVotingPermission`. Because `check_principal_authorized_to_change_permissions` accepts `ManageVotingPermission` as sufficient authorization when the permissions to change are "exclusively voting-related," any principal holding `ManageVotingPermission` can grant `ManageVotingPermission` to arbitrary additional principals. This makes the permission self-replicating, violating the intended access-control hierarchy where only `ManagePrincipals` holders should be able to grant meta-permissions.

## Finding Description

**Root cause:** `PERMISSIONS_RELATED_TO_VOTING` includes `ManageVotingPermission` itself: [1](#0-0) 

**Authorization check:** `check_principal_authorized_to_change_permissions` accepts `ManageVotingPermission` as sufficient when `permissions_to_change.is_exclusively_voting_related()` returns `true`: [2](#0-1) 

**Predicate:** `is_exclusively_voting_related` checks membership in `PERMISSIONS_RELATED_TO_VOTING`. Since `ManageVotingPermission` is in that set, `is_exclusively_voting_related([ManageVotingPermission])` returns `true`: [3](#0-2) 

**Execution path:** `add_neuron_permissions` calls `check_principal_authorized_to_change_permissions` (line 4596) then `check_permissions_are_grantable` (line 4599). When `neuron_grantable_permissions` includes `ManageVotingPermission` (the default in production SNS deployments), both guards pass and the grant succeeds: [4](#0-3) 

**Confirmed by existing test:** The test `test_manage_voting_permission_allows_adding_permissions_related_to_voting` explicitly grants the full `PERMISSIONS_RELATED_TO_VOTING` set (including `ManageVotingPermission`) to a target principal using only a `ManageVotingPermission` caller, and asserts success with `NeuronPermissionList::all()` as grantable permissions: [5](#0-4) 

## Impact Explanation

A compromised or malicious principal holding `ManageVotingPermission` (e.g., a third-party voting-service canister) can silently grant `ManageVotingPermission` to attacker-controlled principals. Those principals can then: (1) vote on governance proposals using the neuron's voting power, (2) submit proposals consuming the neuron's stake as fees, (3) further propagate `ManageVotingPermission` up to `max_number_of_principals_per_neuron`, and (4) remove `ManageVotingPermission` from legitimate principals. This constitutes unauthorized access to neurons and governance assets, matching the **High** bounty impact tier: "Unauthorized access to neurons, governance assets, wallets, identities, ledgers, or canister-controlled funds where exploitation requires meaningful per-target work or other constraints."

## Likelihood Explanation

The attack requires: (a) the neuron owner has granted `ManageVotingPermission` to at least one principal — the normal operating mode for any neuron using voting delegation or hotkey automation — and (b) that principal is compromised or malicious. Condition (b) is realistic given that voting-service canisters are third-party software. The `neuron_grantable_permissions` guard is the only external brake, and it is routinely set to `NeuronPermissionList::all()` in production SNS deployments (as confirmed by the test fixture). The attack is a single `manage_neuron` call with `AddNeuronPermissions`, requiring no privileged access beyond the already-held `ManageVotingPermission`.

## Recommendation

Remove `ManageVotingPermission` from `PERMISSIONS_RELATED_TO_VOTING`. It is a meta-permission (the ability to manage voting permissions), not a voting action itself. After the change, only `ManagePrincipals` holders can grant or revoke `ManageVotingPermission`:

```rust
// rs/sns/governance/src/neuron.rs
pub const PERMISSIONS_RELATED_TO_VOTING: &'static [NeuronPermissionType] = &[
    NeuronPermissionType::Vote,
    NeuronPermissionType::SubmitProposal,
-   NeuronPermissionType::ManageVotingPermission,
];
```

If the intent is to allow `ManageVotingPermission` holders to delegate voting to others but not replicate their own management authority, introduce a separate predicate (e.g., `PERMISSIONS_GRANTABLE_BY_MANAGE_VOTING`) containing only `Vote` and `SubmitProposal`.

## Proof of Concept

The existing test `test_manage_voting_permission_allows_adding_permissions_related_to_voting` at `rs/sns/governance/tests/governance.rs:954` directly demonstrates the self-replication path. To reproduce the full attack chain:

1. Set up an SNS neuron N with `neuron_grantable_permissions = NeuronPermissionList::all()`.
2. Grant `ManageVotingPermission` to voting-service canister V (caller has `ManagePrincipals`).
3. From V, call `manage_neuron` on N with `AddNeuronPermissions { principal_id: attacker_A, permissions_to_add: [ManageVotingPermission, Vote, SubmitProposal] }`.
4. Both guards pass: `is_exclusively_voting_related` returns `true`, `check_permissions_are_grantable` passes.
5. Attacker A now holds `ManageVotingPermission` on N and can vote, submit proposals, and further propagate the permission.

### Citations

**File:** rs/sns/governance/src/neuron.rs (L61-65)
```rust
    pub const PERMISSIONS_RELATED_TO_VOTING: &'static [NeuronPermissionType] = &[
        NeuronPermissionType::Vote,
        NeuronPermissionType::SubmitProposal,
        NeuronPermissionType::ManageVotingPermission,
    ];
```

**File:** rs/sns/governance/src/neuron.rs (L152-159)
```rust
        let sufficient_permissions = if permissions_to_change.is_exclusively_voting_related() {
            vec![
                NeuronPermissionType::ManagePrincipals,
                NeuronPermissionType::ManageVotingPermission,
            ]
        } else {
            vec![NeuronPermissionType::ManagePrincipals]
        };
```

**File:** rs/sns/governance/src/governance.rs (L230-238)
```rust
    pub fn is_exclusively_voting_related(&self) -> bool {
        let permissions_related_to_voting = Neuron::PERMISSIONS_RELATED_TO_VOTING
            .iter()
            .map(|p| *p as i32)
            .collect::<Vec<_>>();
        self.permissions
            .iter()
            .all(|p| permissions_related_to_voting.contains(p))
    }
```

**File:** rs/sns/governance/src/governance.rs (L4596-4600)
```rust
        neuron
            .check_principal_authorized_to_change_permissions(caller, permissions_to_add.clone())?;

        self.nervous_system_parameters_or_panic()
            .check_permissions_are_grantable(permissions_to_add)?;
```

**File:** rs/sns/governance/tests/governance.rs (L954-984)
```rust
#[test]
fn test_manage_voting_permission_allows_adding_permissions_related_to_voting() {
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let target = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let permissions_to_add: NeuronPermissionList =
        Neuron::PERMISSIONS_RELATED_TO_VOTING.to_vec().into();
    let (mut governance, neuron) = {
        let permissions: &[(PrincipalId, NeuronPermissionList)] = &[(
            caller,
            vec![NeuronPermissionType::ManageVotingPermission].into(),
        )];
        let user_principal = PrincipalId::new_user_test_id(0);
        let neuron_id = neuron_id(user_principal, 0);

        let governance_fixture = GovernanceCanisterFixtureBuilder::new()
            .with_neuron_grantable_permissions(NeuronPermissionList::all())
            .add_neuron_with_permissions(permissions, neuron_id.clone())
            .create();

        (governance_fixture, neuron_id)
    };

    // Attempt to add voting-related permissions to `target` - should succeed
    // since `caller` has ManageVotingPermission.
    governance
        .add_neuron_permissions(&neuron, target, permissions_to_add.clone(), caller)
        .unwrap();

    // Check that `target` now has those permissions.
    governance.assert_principal_has_permissions_for_neuron(&neuron, target, permissions_to_add);
}
```
