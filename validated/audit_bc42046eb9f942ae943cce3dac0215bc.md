### Title
Signature verification bypasses to unauthenticated `status` webhook forgery advances a victim's merge queue - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever no `webhook_secret` is configured for the organization resolved from the attacker-controlled payload, and even when a secret exists, only the legacy `sha1=` prefix is accepted. Combined with `StatusHandler#process`, which looks up commits globally by `sha` with no ownership/stack scoping, an attacker who can get any organization mapped by `repository_owner` to accept an unverified (or self-controlled) webhook can post a forged `status` event for a `sha` belonging to a victim's stack and trigger `Commit#add_status` → `stack.schedule_merges`, advancing the victim's merge queue.

### Finding Description
The binding that should hold is: **a `status` webhook mutation for `Commit#id == X` should only be accepted if `X.stack.repository.owner` cryptographically authenticated the payload via its own `webhook_secret`.** In `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`), `repository_owner` is read straight from attacker-controlled JSON (`params.dig('repository','owner','login')`, line 59-62) and used to select the `GitHubApp` instance (`Shipit.github(organization: repository_owner)`). `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) is:
```
return true unless webhook_secret
algorithm, signature = signature.split("=", 2)
return false unless algorithm == 'sha1'
SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
``` [1](#0-0) 
If the resolved organization has no `webhook_secret` configured, verification is skipped entirely — any body/signature is "verified." Downstream, `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no scoping to the repository/owner asserted in the payload: [2](#0-1) 
`create_status_from_github!` → `add_status` schedules merges: `stack.schedule_merges if new_status.pending? || new_status.success?` [3](#0-2) .

Root cause: (1) signature verification keys off attacker-supplied `repository_owner`, and organizations without a configured `webhook_secret` fully bypass verification; (2) even where verification enforces HMAC, only `sha1` is accepted — a downgrade acceptance, though this alone does not permit forgery without knowledge of the secret; (3) the `status` handler correlates purely by commit `sha`, a value that is public (visible in PR/commit metadata, and often the same `sha` is shared across forks/mirrors) and not re-validated against the payload's asserted `repository.full_name`, so a webhook that only "authenticates" as *some* organization can still mutate a commit belonging to a *different* stack/repository as long as the `sha` matches.

**Attacker's exact request:** `POST /webhooks` with header `X-Github-Event: status`, `X-Hub-Signature: sha1=<anything>` (or omitted), and a JSON body `{"sha": "<victim commit sha>", "state": "success", "repository": {"owner": {"login": "<org with no webhook_secret configured>"}}}`. If any organization onboarded to the Shipit instance lacks a `webhook_secret` (a plausible/likely misconfiguration state, e.g., before GitHub App webhook secret rotation, or an org intentionally left without a secret), `verify_signature` accepts the request unconditionally, `drop_unhandled_event` passes because `status` has a registered handler, and `StatusHandler` writes a status onto the victim's commit and can trigger `stack.schedule_merges`.

**Why existing guards fail:** `drop_unhandled_event` only checks the event type is registered, not who sent it. `verify_signature`'s only guard is the HMAC check, which is a no-op for secret-less orgs. `ExplicitParameters` (`StatusHandler.params`) validates shape only, not repository ownership. There is no `stacks`/ownership check in `StatusHandler#process` unlike, e.g., `CheckSuiteHandler`, which at least scopes via `stacks.where(branch: ...)` [4](#0-3) .

### Impact Explanation
A forged `status` webhook can flip a victim commit's status to `success`/`pending`, which is the exact trigger `Commit#add_status` uses to call `stack.schedule_merges` [3](#0-2) , causing `ProcessMergeRequestsJob` to re-evaluate and potentially merge pending merge requests on the victim's stack [5](#0-4) . This is an unauthorized manipulation of another tenant's merge queue state, matching the "unauthorized deploy/merge" Critical category, contingent entirely on the precondition below.

### Likelihood Explanation
This is conditional, not universally exploitable: it requires that **at least one organization configured in `Shipit.github_organizations`/`secrets.github` has no `webhook_secret` set** (`GitHubApp#verify_webhook_signature` line 77 `return true unless webhook_secret`), OR that the attacker can name `repository_owner` such that `Shipit.github(organization: repository_owner)` resolves to an org they legitimately control (in which case they are only forging events for their own org's webhook_secret domain — not a "victim"). The described chain additionally requires that the attacker knows a victim commit `sha` (generally obtainable, since shas are not secrets) belonging to some stack tracked by the instance. The "legacy sha1" framing does not by itself enable forgery against a properly-secreted org — HMAC-SHA1 is not a length-extension-vulnerable construction and the attacker still needs the secret to compute a valid `sha1=` MAC. The exploitable condition is strictly the **no-secret org bypass** in `verify_webhook_signature`, not the sha1-vs-sha256 algorithm choice. I could not verify from the code alone whether production Shipit deployments always configure a `webhook_secret` per org (this is operator configuration, outside this engine's code, and I found no code path that enforces `webhook_secret` presence at startup).

### Recommendation
1. Do not allow `verify_webhook_signature` to short-circuit to `true` when `webhook_secret` is blank; treat missing secret as a fail-closed configuration error (reject with 422/500) rather than fail-open.
2. Scope `StatusHandler#process` (and any other sha-keyed handler) to commits belonging to the repository asserted by the verified payload (`payload.dig('repository','full_name')`), not a global `Commit.where(sha: ...)` lookup.
3. Optionally support and prefer `X-Hub-Signature-256`, but this is secondary to fixing the fail-open no-secret path.

### Proof of Concept
```ruby
test "status webhook for an org with no webhook_secret configured is accepted and advances the victim's merge queue" do
  victim_commit = shipit_commits(:first) # belongs to a stack the attacker does not own
  attacker_owner = "org-without-secret"

  # Precondition: GitHubApp for `attacker_owner` has no webhook_secret configured
  Shipit.stubs(:github).with(organization: attacker_owner)
        .returns(Shipit::GitHubApp.new(attacker_owner, { app_id: 1, installation_id: 1, private_key: nil }))

  request.headers['X-Github-Event'] = 'status'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary, unverifiable, attacker has no secret

  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => attacker_owner }, 'full_name' => 'attacker/unrelated-repo' }
  }.to_json

  assert_enqueued_with(job: Shipit::ProcessMergeRequestsJob, args: [victim_commit.stack]) do
    post :create, body: body, as: :json
  end
  assert_response :ok

  # Equality check before/after: victim_commit.stack authenticated the mutation? should be false, but state changed anyway.
  assert_equal 'success', victim_commit.reload.state
end
```
This demonstrates the binding "a mutation on `victim_commit.stack` requires `victim_commit.stack.repository.owner`'s secret to have verified the payload" is violated: the payload was verified (or fail-open accepted) under `attacker_owner`'s (non-existent) secret, yet it mutated `victim_commit`, which belongs to an unrelated stack/owner.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
```
