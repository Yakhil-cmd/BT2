No vulnerability found for this question.

The reported CVE describes a Linux kernel `nfsd4_create()` C bug: a designated-initializer struct copy steals `cr_dpacl`/`cr_pacl` into a local `nfsd_attrs`, nils the source fields, and then a conflict guard mistakenly re-checks the now-nulled source fields instead of the destination, making the check permanently dead and leaking `posix_acl` slab objects. This is a very C-specific memory-management defect (manual struct field lifetime/ownership tracking with raw pointers and slab allocation) tied to NFSv4 ACL bitmap handling.

I searched the Polkadot SDK codebase for analogous patterns — steal-into-local-struct-then-nil-source-then-check-stale-source guard leading to leaked/duplicated resources — across FRAME pallets (assets, contracts/revive transient storage, dispatch context), consensus (GRANDPA import authority-set guards), and node-side approval-voting/networking code. None of these exhibit the same defect class: [1](#0-0) , [2](#0-1) , and [3](#0-2)  all use `Option::take()`/ownership-transfer patterns, but their subsequent checks correctly operate on the moved-to destination or otherwise correctly guarded state — there's no case found where a check inspects an already-nilled source that was the origin of a steal, producing dead code and a resource/reference leak.

Since Rust's ownership model (move semantics, `Option::take()`, borrow checker) structurally prevents the C-style "raw pointer stays valid after struct copy, original not cleared automatically" bug class that enabled this CVE, and no equivalent double-free/leak-via-dead-guard pattern was found in reachable, non-test/non-mock production code, there is no demonstrable Polkadot SDK analog to report.

### Citations

**File:** substrate/frame/assets/src/functions.rs (L382-384)
```rust
		if let Some(deposit) = account.reason.take_deposit() {
			T::Currency::unreserve(&who, deposit);
		}
```

**File:** substrate/frame/revive/src/transient_storage.rs (L240-248)
```rust
	pub fn write(
		&mut self,
		account: &AccountIdOf<T>,
		key: &Key,
		value: Option<Vec<u8>>,
		take: bool,
	) -> Result<WriteOutcome, DispatchError> {
		let key = Self::storage_key(&account.encode(), &key.hash());
		let prev_value = self.storage.read(&key);
```

**File:** substrate/client/consensus/grandpa/src/import.rs (L293-325)
```rust
		struct InnerGuard<'a, H, N> {
			old: Option<AuthoritySet<H, N>>,
			guard: Option<SharedDataLocked<'a, AuthoritySet<H, N>>>,
		}

		impl<'a, H, N> InnerGuard<'a, H, N> {
			fn as_mut(&mut self) -> &mut AuthoritySet<H, N> {
				self.guard.as_mut().expect("only taken on deconstruction; qed")
			}

			fn set_old(&mut self, old: AuthoritySet<H, N>) {
				if self.old.is_none() {
					// ignore "newer" old changes.
					self.old = Some(old);
				}
			}

			fn consume(
				mut self,
			) -> Option<(AuthoritySet<H, N>, SharedDataLocked<'a, AuthoritySet<H, N>>)> {
				self.old
					.take()
					.map(|old| (old, self.guard.take().expect("only taken on deconstruction; qed")))
			}
		}

		impl<'a, H, N> Drop for InnerGuard<'a, H, N> {
			fn drop(&mut self) {
				if let (Some(mut guard), Some(old)) = (self.guard.take(), self.old.take()) {
					*guard = old;
				}
			}
		}
```
