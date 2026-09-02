### Title
StatusHandler#process globally matches commits by `sha` with no repository scoping, allowing an authenticated attacker-org webhook to mutate a victim-org's commit status - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` only authenticates that a request's `X-Hub-Signature` matches the `webhook_secret` of `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled JSON body. It says nothing about which specific repository/stack the payload is allowed to mutate. `StatusHandler#process` then ignores the payload's `repository` entirely and does a repository-agnostic query, `Commit.where(sha: params.sha)`, across the whole `commits` table, mutating whatever commit(s) match that sha regardless of owning stack/repository.

### Finding Description
The claimed binding is:
`repository_owner` (the org whose secret verified the signature) `== owner of every repository/stack mutated by the resulting handler call`.

Tracing the code:
- `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. This only proves the request was signed by the secret configured for that organization; it never checks that the organization actually owns the specific repository/commit that the handler will touch.
- `WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) re-parses the raw body and dispatches it unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.
- The base `Handler` class provides a `stacks` helper method that scopes to `Repository.from_github_repo_name(repository_name)&.stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38), which is exactly the mechanism that would enforce the binding. `PushHandler#process` uses this helper (`stacks.not_archived.where(branch:)...`), correctly scoping mutations to the repository named in the payload (app/models/shipit/webhooks/handlers/push_handler.rb:12-17).
- `StatusHandler#process`, however, does **not** use `stacks` at all: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24). This matches by `sha` value only, globally, independent of the `repository` field in the same payload used for authentication.

Because `sha` is a value the attacker fully controls in the JSON body, and commit SHAs of public repositories are knowable/guessable (they aren't secrets — they're visible on GitHub commit pages, PRs, CI logs, etc.), an attacker who legitimately controls one org onboarded into the same multi-tenant Shipit instance (`Shipit.github(organization: 'attacker-org')` with a real `webhook_secret` they control) can:
1. Look up any commit sha belonging to a victim-org's stack tracked by the same Shipit instance.
2. Send a `status` event webhook signed with their own org's secret, with `repository.owner.login = 'attacker-org'` (so `verify_signature` passes) but `sha` set to the victim's commit sha.
3. `StatusHandler#process` finds the victim's `Commit` record purely by sha match and calls `commit.create_status_from_github!(params)` on it, creating a `Status` under the victim's stack with attacker-supplied `state`, `description`, `target_url`, and `context`.

Downstream effects of `create_status_from_github!` / `add_status` (app/models/shipit/commit.rb:366-386) include emitting `commit_status`/`deployable_status` hooks and calling `stack.schedule_merges` when the status becomes `pending` or `success` — i.e., the forged status can influence merge/deploy scheduling for the victim stack (app/models/shipit/commit.rb:379-384).

None of the listed guards prevent this: `verify_signature` authenticates the org, not the repository/commit being mutated; `drop_unhandled_event` only filters by event type; the `ExplicitParameters` schema for `StatusHandler` only validates `sha`/`state` types, not ownership; there is no `stacks`-based scoping applied in `StatusHandler#process` unlike `PushHandler`.

### Impact Explanation
An attacker who legitimately controls one organization onboarded into a shared/multi-tenant Shipit instance can create or influence `Status` records — and thus deploy/merge scheduling signals — for commits belonging to a completely different organization's stack, without ever needing to forge a signature or steal any secret. This is a cross-tenant write ("a payload for one repository mutating another's stack, commit... "), matching the Critical impact category. The attack is repeatable against any commit sha the attacker can learn, for any org sharing the Shipit instance.

### Likelihood Explanation
Requires: (a) the Shipit deployment to host multiple GitHub organizations/tenants (`Shipit.github(organization: ...)` configured per-org), (b) attacker to legitimately control one such onboarded org with a valid `webhook_secret` for their own repos, and (c) knowledge of a target commit sha in a victim stack (commonly public information). No GitHub/Shipit secret theft, signature forgery, or privileged Shipit role is required — cost to the attacker is low and the request is trivially repeatable.

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring `PushHandler`, e.g. restrict the commit lookup to `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` (or equivalent using the `stacks` helper from the base `Handler`), so a status webhook can only mutate commits belonging to stacks under the repository that was actually authenticated by `verify_signature`.

### Proof of Concept
Minitest plan (test/models/shipit/webhooks/handlers/status_handler_test.rb or webhooks_controller_test.rb):
```ruby
test "status webhook cannot mutate a commit belonging to a different repository/org" do
  victim_stack = shipit_stacks(:shipit) # e.g. repository owned by "shopify"
  victim_commit = shipit_commits(:first)
  victim_commit.update!(sha: "deadbeef" * 5)

  # Simulate attacker-org's webhook, correctly signed for attacker-org,
  # but repository field references attacker-org, not the victim's org.
  GithubHook.any_instance.stubs(:verify_webhook_signature).returns(true) # only true for attacker-org's secret path

  payload = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "repository" => { "owner" => { "login" => "attacker-org" }, "full_name" => "attacker-org/some-repo" }
  }.to_json

  request.headers['X-Github-Event'] = 'status'
  request.headers['X-Hub-Signature'] = 'sha1=validforattackerorgsecret'

  assert_no_difference "victim_commit.statuses.count" do  # EXPECTED after fix; currently FAILS (difference of 1)
    post :create, body: payload, as: :json
  end
end
```
Before the fix, this assertion fails because `StatusHandler#process` matches `victim_commit` purely by `sha` and creates a `Status` under it despite the payload's `repository.owner.login` being `attacker-org`, proving the binding `repository_owner (authenticated) == owner of mutated stack` does not hold. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L26-38)
```ruby
        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
