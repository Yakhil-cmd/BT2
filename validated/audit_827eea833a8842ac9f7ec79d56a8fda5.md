[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [2](#0-1)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/cache/move_cache.rs (L86-110)
```rust
    pub(crate) fn add_package_to_cache(
        &self,
        package_key: VersionId,
        verified: verification::ast::Package,
        runtime: jit::execution::ast::Package,
    ) -> bool {
        use dashmap::mapref::entry::Entry;
        // Grab the entry at the top, so we can figure out which flag to return while holding the
        // lock on the shard of dashmap we are modifying (so this does not change out from under us
        // mid-write).
        let entry = self.package_cache.entry(package_key);
        match entry {
            Entry::Occupied(_) => {
                // Package is already present.
                false
            }
            Entry::Vacant(vacant_entry) => {
                let verified = Arc::new(verified);
                let runtime = Arc::new(runtime);
                let package = Package { verified, runtime };
                vacant_entry.insert(Arc::new(package));
                true
            }
        }
    }
```

**File:** external-crates/move/crates/move-vm-runtime/src/runtime/package_resolution.rs (L196-220)
```rust
pub(crate) fn jit_package_for_publish(
    telemetry: &mut TransactionTelemetryContext,
    cache: &MoveCache,
    natives: &NativeFunctions,
    verified_pkg: verification::ast::Package,
) -> VMResult<Arc<move_cache::Package>> {
    let version_id = verified_pkg.version_id;
    if let Some(pkg) = cache.cached_package_at(version_id) {
        return Ok(pkg);
    }

    let timer = telemetry.make_timer_with_count(crate::runtime::telemetry::TimerKind::JIT, 1);
    let runtime_pkg = jit::translate_package(
        &cache.vm_config,
        &cache.interner,
        natives,
        verified_pkg.clone(),
    )
    .map_err(|err| err.finish(Location::Package(version_id)));
    telemetry.report_time(timer);
    Ok(Arc::new(Package::new(
        verified_pkg.into(),
        runtime_pkg?.into(),
    )))
}
```

**File:** external-crates/move/crates/move-vm-runtime/src/runtime/package_resolution.rs (L223-262)
```rust
pub(crate) fn jit_and_cache_package(
    telemetry: &mut TransactionTelemetryContext,
    cache: &MoveCache,
    natives: &NativeFunctions,
    verified_pkg: verification::ast::Package,
) -> VMResult<Arc<move_cache::Package>> {
    let version_id = verified_pkg.version_id;
    // If the package is already in the cache, return it.
    // This is possible since the cache is shared and may be inserted into concurrently by other
    // VMs working over the same cache.
    if let Some(pkg) = cache.cached_package_at(version_id) {
        return Ok(pkg);
    }

    let timer = telemetry.make_timer_with_count(crate::runtime::telemetry::TimerKind::JIT, 1);
    let runtime_pkg = jit::translate_package(
        &cache.vm_config,
        &cache.interner,
        natives,
        verified_pkg.clone(),
    )
    .map_err(|err| err.finish(Location::Package(version_id)));
    telemetry.report_time(timer);

    let fresh_insert_to_cache = cache.add_package_to_cache(version_id, verified_pkg, runtime_pkg?);

    // If we compiled the package, but another thread already inserted it during compilation,
    // record that this was a redundant compilation for telemetry and move on.
    if !fresh_insert_to_cache {
        telemetry.record_redundant_compilation();
    }

    // SAFETY: We call an `expect` as opposed to raising an invariant violation here since if we
    // fail to find the package right after inserting it, the cache is in a broken state and there
    // is no recovery from this point forward, so we must panic and crash the process rather than
    // trying to continue in a broken state.
    #[allow(clippy::expect_used)]
    Ok(cache.cached_package_at(version_id).expect(
        "Package must be in cache after inserting it otherwise cache is irreparably broken",
    ))
```

**File:** external-crates/move/crates/move-vm-runtime/src/shared/types.rs (L14-17)
```rust
/// Version ID: the ID of a given version of the package.
/// For v0 this matches the original ID; for all others it is the on-chain publication ID of that
/// package version. This is use for linkage contexts, etc.
pub type VersionId = AccountAddress;
```
