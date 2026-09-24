No vulnerability found for this question.

I investigated the closest structural analog to Warpgate's SSO CSRF (a "request → correlation token → response" flow with a missing state check): XCM's `QueryResponse` mechanism in `pallet-xcm` and `xcm-executor`, since it also involves an original request (`new_query`/`report_outcome`) later completed by an asynchronous response that must be matched back to the correct requester.

Unlike the Warpgate bug (state parameter generated but never validated on return), the polkadot-sdk XCM response path binds and validates its correlation state on every dimension:

- The `Pending` query status stores the expected `responder` location and an optional `maybe_match_querier`, keyed by `query_id` [1](#0-0) .
- `OnResponse::on_response` re-checks the incoming `origin` against the stored `responder`, and if a querier was registered, requires the response's `querier` field to match it exactly, emitting `InvalidQuerier`/`InvalidResponder` events and returning early (no state mutation, no notify dispatch) on mismatch [2](#0-1) .
- The barrier `AllowKnownQueryResponses` additionally gates execution of the `QueryResponse` instruction itself, only allowing it through if `ResponseHandler::expecting_response(origin, query_id, querier)` returns true, which re-derives the same responder/querier checks before the instruction is even processed [3](#0-2) [4](#0-3) .
- Tests explicitly exercise the "wrong querier" / "missing querier" cases and confirm they are rejected rather than silently accepted [5](#0-4) .

So the necessary precondition for the Warpgate-class bug — a correlation/state token that is issued but not verified on the return path — does not hold here: `query_id` alone is not trusted, the responder location and (when configured) querier are cryptographically/structurally bound and checked before any effect (including dispatching a `notify` callback) occurs. I did not find another user-reachable "issue token now, redeem later without validating who redeems it" pattern elsewhere in the scanned code (e.g., proxy announcements and multisig approvals bind to `(who, call_hash, timepoint)` rather than an unauthenticated bearer token, which is a materially different trust model from an SSO state parameter). [6](#0-5)

### Citations

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L770-783)
```rust
	/// The status of a query.
	#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
	pub enum QueryStatus<BlockNumber> {
		/// The query was sent but no response has yet been received.
		Pending {
			/// The `QueryResponse` XCM must have this origin to be considered a reply for this
			/// query.
			responder: VersionedLocation,
			/// The `QueryResponse` XCM must have this value as the `querier` field to be
			/// considered a reply for this query. If `None` then the querier is ignored.
			maybe_match_querier: Option<VersionedLocation>,
			maybe_notify: Option<(u8, u8)>,
			timeout: BlockNumber,
		},
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L4030-4050)
```rust
impl<T: Config> OnResponse for Pallet<T> {
	fn expecting_response(
		origin: &Location,
		query_id: QueryId,
		querier: Option<&Location>,
	) -> bool {
		match Queries::<T>::get(query_id) {
			Some(QueryStatus::Pending { responder, maybe_match_querier, .. }) => {
				Location::try_from(responder).map_or(false, |r| origin == &r) &&
					maybe_match_querier.map_or(true, |match_querier| {
						Location::try_from(match_querier).map_or(false, |match_querier| {
							querier.map_or(false, |q| q == &match_querier)
						})
					})
			},
			Some(QueryStatus::VersionNotifier { origin: r, .. }) => {
				Location::try_from(r).map_or(false, |r| origin == &r)
			},
			_ => false,
		}
	}
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L4104-4146)
```rust
			(
				response,
				Some(QueryStatus::Pending { responder, maybe_notify, maybe_match_querier, .. }),
			) => {
				if let Some(match_querier) = maybe_match_querier {
					let match_querier = match Location::try_from(match_querier) {
						Ok(mq) => mq,
						Err(_) => {
							Self::deposit_event(Event::InvalidQuerierVersion {
								origin: origin.clone(),
								query_id,
							});
							return Weight::zero();
						},
					};
					if querier.map_or(true, |q| q != &match_querier) {
						Self::deposit_event(Event::InvalidQuerier {
							origin: origin.clone(),
							query_id,
							expected_querier: match_querier,
							maybe_actual_querier: querier.cloned(),
						});
						return Weight::zero();
					}
				}
				let responder = match Location::try_from(responder) {
					Ok(r) => r,
					Err(_) => {
						Self::deposit_event(Event::InvalidResponderVersion {
							origin: origin.clone(),
							query_id,
						});
						return Weight::zero();
					},
				};
				if origin != responder {
					Self::deposit_event(Event::InvalidResponder {
						origin: origin.clone(),
						query_id,
						expected_location: Some(responder),
					});
					return Weight::zero();
				}
```

**File:** polkadot/xcm/xcm-builder/src/barriers.rs (L446-472)
```rust
/// Allows only messages if the generic `ResponseHandler` expects them via `expecting_response`.
pub struct AllowKnownQueryResponses<ResponseHandler>(PhantomData<ResponseHandler>);
impl<ResponseHandler: OnResponse> ShouldExecute for AllowKnownQueryResponses<ResponseHandler> {
	fn should_execute<RuntimeCall>(
		origin: &Location,
		instructions: &mut [Instruction<RuntimeCall>],
		max_weight: Weight,
		properties: &mut Properties,
	) -> Result<(), ProcessMessageError> {
		tracing::trace!(
			target: "xcm::barriers",
			?origin, ?instructions, ?max_weight, ?properties,
			"AllowKnownQueryResponses"
		);
		instructions
			.matcher()
			.assert_remaining_insts(1)?
			.match_next_inst(|inst| match inst {
				QueryResponse { query_id, querier, .. }
					if ResponseHandler::expecting_response(origin, *query_id, querier.as_ref()) =>
				{
					Ok(())
				},
				_ => Err(ProcessMessageError::BadFormat),
			})?;
		Ok(())
	}
```

**File:** polkadot/xcm/pallet-xcm/src/tests/mod.rs (L220-270)
```rust
		// Supplying no querier when one is expected will fail
		let message = Xcm(vec![QueryResponse {
			query_id: 0,
			response: Response::ExecutionResult(None),
			max_weight: Weight::zero(),
			querier: None,
		}]);
		let mut hash = fake_message_hash(&message);
		let r = XcmExecutor::<XcmConfig>::prepare_and_execute(
			AccountId32 { network: None, id: ALICE.into() },
			message,
			&mut hash,
			Weight::from_parts(1_000_000_000, 1_000_000_000),
			Weight::from_parts(1_000, 1_000),
		);
		assert_eq!(r, Outcome::Complete { used: Weight::from_parts(1_000, 1_000) });
		assert_eq!(
			last_event(),
			RuntimeEvent::XcmPallet(crate::Event::InvalidQuerier {
				origin: AccountId32 { network: None, id: ALICE.into() }.into(),
				query_id: 0,
				expected_querier: querier.clone(),
				maybe_actual_querier: None,
			}),
		);

		// Supplying the wrong querier will also fail
		let message = Xcm(vec![QueryResponse {
			query_id: 0,
			response: Response::ExecutionResult(None),
			max_weight: Weight::zero(),
			querier: Some(Location::here()),
		}]);
		let mut hash = fake_message_hash(&message);
		let r = XcmExecutor::<XcmConfig>::prepare_and_execute(
			AccountId32 { network: None, id: ALICE.into() },
			message,
			&mut hash,
			Weight::from_parts(1_000_000_000, 1_000_000_000),
			Weight::from_parts(1_000, 1_000),
		);
		assert_eq!(r, Outcome::Complete { used: Weight::from_parts(1_000, 1_000) });
		assert_eq!(
			last_event(),
			RuntimeEvent::XcmPallet(crate::Event::InvalidQuerier {
				origin: AccountId32 { network: None, id: ALICE.into() }.into(),
				query_id: 0,
				expected_querier: querier.clone(),
				maybe_actual_querier: Some(Location::here()),
			}),
		);
```

**File:** RESEARCHER.md (L129-139)
```markdown
### Using Prior Reports as Research Leads

A report from another project or domain, including a Solidity audit finding,
can suggest a general bug class or invariant. It is not evidence that the
target has the same vulnerability.

- Extract the failure mechanism and its necessary preconditions.
- Determine whether the target has an equivalent boundary and reachable path.
- Verify the target's checks and behavior independently.
- Reject the analogy when its preconditions do not hold; explain why.
- Do not carry over the source report's severity, impact, or PoC unchanged.
```
