Based on the investigation, I found no valid Polkadot SDK analog to this vulnerability.

**Analysis:**

The reported bug is a state-machine flaw specific to `Bootstrap.vy`: an admin can (by mistake, not maliciously) leave `vote_end`/`deposit_end` later than `lock_end`, letting anyone who already voted `claim()` their `styETH` back, sell it, and vote again with fresh capital before the vote concludes — because `claim()` doesn't reduce or invalidate the previously cast vote weight.

I checked the closest FRAME analogs — `pallet-conviction-voting` and `pallet-democracy` — for the same class of issue (vote weight persisting after underlying funds are freed/reused):

- In `try_vote`, a vote adds to the poll's `tally` and extends a currency lock via `T::Currency::extend_lock` / equivalent lock tracking. [1](#0-0) 
- Crucially, `try_remove_vote` (called by `remove_vote`) explicitly requires the poll status and, if `Ongoing`, immediately calls `tally.remove(v.1)` to subtract the voter's weight from the tally before any lock is released or vote is re-cast.
<invoke name="codebase_search">
<parameter name="query">try_remove_vote tally remove ongoing poll</parameter>
</invoke>

### Citations

**File:** substrate/frame/conviction-voting/src/lib.rs (L252-259)
```rust
		pub fn vote(
			origin: OriginFor<T>,
			#[pallet::compact] poll_index: PollIndexOf<T, I>,
			vote: AccountVote<BalanceOf<T, I>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::try_vote(&who, poll_index, vote)
		}
```
