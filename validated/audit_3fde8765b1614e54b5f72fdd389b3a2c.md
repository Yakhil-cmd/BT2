### Title
StatusHandler resolves target commits by SHA alone with no repository binding, letting any correctly-signed webhook forge `state: success` on another repository's commit and trigger unauthorized continuous deployment - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Handler` (the base class for all webhook handlers) exposes a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, and `PushHandler`/`CheckSuiteHandler` use it. `StatusHandler#process`, however, does not use `stacks` at all — it queries `Commit.where(sha: params.sha)` globally, across every stack in the installation, and writes a `Status` for every match regardless of which repository the inbound payload's `repository.full_name`/`repository_owner` claims to be. If the SHA in the payload happens to also exist as a `Commit` row belonging to a different (victim) stack, that victim's commit gets a forged status, and `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` will enqueue `ContinuousDeliveryJob` for the victim stack once `deployable?`/`stack.continuous_deployment?` are satisfied.

### Finding Description
Broken binding as an equality: the code path implicitly assumes `commit.stack == Repository.from_github_repo_name(payload['repository']['full_name']).stacks` for every handler, but `StatusHandler` never performs that comparison — `Commit.where(sha: params.sha)` is unconstrained by `payload['repository']`. So the equality `commit.stack (victim) == authenticated_repository (attacker's own signed org)` is never checked, and yet `commit.stack`'s `continuous_deployment?` flag (set only by the victim's admin) is what authorizes `ContinuousDeliveryJob.perform_later(stack)`.

Code path:
- `app/models/shipit/webhooks/handlers/handler.rb:32-38` defines `stacks` scoped by `payload.dig('repository','full_name')`, used correctly by `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`).
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) instead does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — no `stacks`, no repository filter at all.
- `Commit#create_status_from_github!` → `Status.replicate_from_github!(stack_id, github_status)` (`app/models/shipit/commit.rb:165-169`, `app/models/shipit/status.rb:24-33`) creates a `Status` with `state: params.state` for the matched commit's own `stack_id` (the victim's stack, taken from the DB row, not from the payload).
- `after_commit :schedule_continuous_delivery` on `Status` (`app/models/shipit/status.rb:19,42-44`) calls `commit.schedule_continuous_delivery`.
- `Commit#schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`): `return unless deployable? && stack.continuous_deployment? && stack.deployable?` then `ContinuousDeliveryJob.set(wait: ...).perform_later(stack)` — `stack` here is the **victim's** `commit.stack`.
- `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`): `!locked? && (stack.ignore_ci? || (success? && !blocked?))`. For a stack with `ignore_ci? == false`, forging `state: success` for the targeted SHA is sufficient to flip `success?` true and satisfy `deployable?` (assuming not locked/blocked).

Why signature verification does not stop this: `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only checks that the HMAC over the raw body is valid for the GitHub App configured for `repository_owner` (taken straight from the *attacker-supplied* `payload['repository']['owner']['login']`). It never checks that the `sha` in the body, or any commit matched by that sha, actually belongs to that same organization/repository. So an attacker who legitimately controls a repository with the Shipit GitHub App installed (or whose org's `webhook_secret` they can produce a valid signature for — e.g., an unconfigured/blank `webhook_secret`, which `verify_webhook_signature` treats as "always verified": `return true unless webhook_secret`, `lib/shipit/github_app.rb:76-77`) can send a `status` event whose `repository` block names their own org (to pass signature verification) while the `sha` field names a commit that exists in a *different* stack. The commit lookup in `StatusHandler` ignores the `repository` block entirely and matches purely on `sha`.

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: status`, a valid `X-Hub-Signature` for the attacker's own configured/known org, and JSON body `{"repository": {"full_name": "attacker/repo", "owner": {"login": "attacker-org"}}, "sha": "<victim-commit-sha>", "state": "success", ...}`.

Preconditions for the sha collision to be meaningful: the attacker needs the victim's stack to already contain a `Commit` record with a `sha` known/guessable to the attacker (e.g. the victim repo is public, or the attacker previously interacted with/forked it so shared history SHAs are known) and a valid signature usable for some org (their own, if `webhook_secret` isn't set for that org, or if they legitimately operate a repo under an org onboarded to the same Shipit instance).

### Impact Explanation
This is a payload for one repository (the attacker's) mutating another repository's (the victim's) `Commit`/`Status` records and, if `continuous_deployment?` is enabled on the victim stack, causing an unauthorized `ContinuousDeliveryJob` to run `stack.trigger_continuous_delivery`, which can trigger a real deploy of the victim's application (`Critical` — "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy"). It is repeatable against any stack whose commits' SHAs the attacker can predict or reuse, limited only by whether the attacker can get any correctly-signed webhook accepted at all by the shared `/webhooks` endpoint.

### Likelihood Explanation
Requires: (1) the attacker be able to produce a request that passes `verify_signature` for *some* organization known to `Shipit.github` (this is either trivial if that org's `webhook_secret` is unset — the documented "optional" default in `config/secrets.*.yml` and `template.rb` — or requires a legitimate webhook secret the attacker already has for their own onboarded org); (2) a target commit `sha` shared between the attacker-controlled context and the victim stack's `commits` table; (3) the victim stack having `continuous_deployment: true` and `ignore_ci: false`, unlocked, unblocked. Given multi-tenant Shipit deployments (the README/docs explicitly document "Using Multiple GitHub Applications" for multiple orgs sharing one Shipit instance) and public GitHub history sharing identical SHAs across forks, this is a realistic, low-cost, repeatable attack whenever the underlying signature-verification precondition holds for the attacker's own org.

### Recommendation
In `StatusHandler#process`, scope the commit lookup through the payload's own repository, mirroring `PushHandler`/`CheckSuiteHandler`, e.g. `stacks.flat_map(&:commits).... .where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a status can only be attached to commits belonging to stacks whose `Repository` matches `payload['repository']['full_name']`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "status webhook cannot set state for a commit belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit) # repository: shopify/shipit-engine, continuous_deployment: true
  victim_commit = victim_stack.commits.create!(sha: "deadbeefcafebabe00000000000000000000001", ...)

  request.headers['X-Github-Event'] = 'status'
  attacker_payload = {
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } },
    'sha' => victim_commit.sha,
    'state' => 'success'
  }.to_json

  GithubHook.any_instance.stubs(:verify_signature).returns(true) # signature valid for attacker-org only

  assert_no_enqueued_jobs(only: Shipit::ContinuousDeliveryJob) do
    post :create, body: attacker_payload, as: :json
  end

  refute victim_commit.reload.success?
end
```
This test currently **fails** against `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) because `Commit.where(sha: params.sha)` finds `victim_commit` irrespective of `attacker_payload['repository']`, creates a `success` `Status` for it, and (with `continuous_deployment?` true on the victim stack) enqueues `ContinuousDeliveryJob` via `assert_enqueued_with(job: ContinuousDeliveryJob, args: [victim_stack])`.