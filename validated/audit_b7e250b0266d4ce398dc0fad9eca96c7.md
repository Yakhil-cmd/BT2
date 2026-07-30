[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/runtime/package_resolution.rs (L39-45)
```rust
    let mut packages = resolve_packages(
        store,
        telemetry,
        cache,
        natives,
        BTreeSet::from([package_to_read]),
    )?;
```

**File:** external-crates/move/crates/move-vm-runtime/src/runtime/package_resolution.rs (L51-58)
```rust
    let Some(pkg) = packages.remove(&package_to_read) else {
        debug_assert!(false, "A different package was loaded than was requested");
        return Err(partial_vm_error!(
            UNKNOWN_INVARIANT_VIOLATION_ERROR,
            "Package not found in loaded cache despite just loading it"
        )
        .finish(Location::Package(package_to_read)));
    };
```

**File:** external-crates/move/crates/move-vm-runtime/src/runtime/package_resolution.rs (L95-110)
```rust
    for pkg_id in packages_to_read {
        if let Some(pkg) = cache.cached_package_at(pkg_id) {
            cached_packages.insert(pkg_id, pkg);
        } else {
            pkgs_to_cache.insert(pkg_id);
        }
    }

    // Load and cache anything that wasn't already there.
    // NB: packages can be loaded out of order here (e.g., in parallel) if so desired.
    for pkg in load_and_verify_packages(store, telemetry, &cache.vm_config, natives, &pkgs_to_cache)
        .map_err(expect_no_verification_errors)?
    {
        let pkg = jit_and_cache_package(telemetry, cache, natives, pkg)?;
        cached_packages.insert(pkg.verified.version_id, pkg);
    }
```

**File:** external-crates/move/crates/move-vm-runtime/src/runtime/package_resolution.rs (L160-175)
```rust
    let ids = ids.iter().copied().collect::<Vec<_>>();
    let pkgs = match store.get_packages(ids.iter()) {
        Ok(pkgs) => pkgs
            .into_iter()
            .enumerate()
            .map(|(idx, pkg)| {
                pkg.ok_or_else(|| {
                    let addr = match ids.safe_get(idx) {
                        Ok(addr) => addr,
                        Err(e) => return e.finish(Location::Undefined),
                    };
                    partial_vm_error!(LINKER_ERROR, "Cannot find package {addr:?} in data cache")
                        .finish(Location::Package(*addr))
                })
            })
            .collect::<VMResult<Vec<_>>>()?,
```

**File:** external-crates/move/crates/move-vm-runtime/src/runtime/package_resolution.rs (L186-192)
```rust
    // Should all be the same length, the the ordering should be preserved.
    debug_assert_eq!(pkgs.len(), ids.len());
    for (pkg, id) in pkgs.iter().zip(ids.iter()) {
        debug_assert_eq!(pkg.version_id, *id);
    }

    Ok(pkgs)
```

**File:** external-crates/move/crates/move-vm-runtime/src/cache/move_cache.rs (L114-119)
```rust
    pub(crate) fn cached_package_at(&self, package_key: VersionId) -> Option<Arc<Package>> {
        self.package_cache
            .get(&package_key)
            .as_deref()
            .map(Arc::clone)
    }
```
