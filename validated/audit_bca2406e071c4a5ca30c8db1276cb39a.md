Confirmed. `Commit#create_status_from_github!` at `app/models/shipit/commit.rb:165-169` performs no repository/organization check whatsoever — it just calls `statuses.replicate_from_github!(stack_id, github_status)` using the commit's own `stack_id`, with zero validation that the webhook's signer owns that stack.

### Title
Cross-organization CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit purely by a global `sha` lookup (`Commit.where(sha: params.sha)`) with no repository or organization scoping, unlike every other webhook handler in this codebase (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) which all resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any stack data. Because `WebhooksController#verify_signature` only checks that the payload's signature matches the secret of whichever organization the *attacker-controlled* `repository.owner.login` field names, an attacker who owns any Shipit-connected org (OrgA) can sign a `status` payload with OrgA's secret while naming a `sha` belonging to a completely different org's (OrgB's) commit, causing a forged `success` status to be written onto OrgB's commit.

### Finding Description
The broken binding: the org that cryptographically signed the request (`repository_owner` = OrgA, verified via `Shipit.github(organization: repository_owner).verify_webhook_signature`) is never checked to equal the org that owns the matched `Commit` row. `Commit#stack#repository#full_name` (OrgB) ≠ `params.dig('repository','owner','login')` (OrgA), yet no code compares them.

Path:
1. `WebhooksController#create` parses the JSON body and dispatches to `Shipit::Webhooks.for_event('status')`, which is `[Handlers::StatusHandler]` (`app/models/shipit/webhooks.rb:19`).
2. `before_action :verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-38`) calls `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-supplied `repository.owner.login` (or `organization.login`) field (`app/controllers/shipit/webhooks_controller.rb:59-62`). Signing with OrgA's real secret against a payload that names OrgA as `repository.owner.login` passes verification — nothing here says the `sha` in the body must belong to OrgA.
3. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does:
   ```ruby
   Commit.where(sha: params.sha).each do |commit|
     commit.create_status_from_github!(params)
   end
   ```
   There is no call to `Handler#stacks` (which would scope by `Repository.from_github_repo_name(repository_name)`), and the `params` schema (lines 7-18) doesn't even require a `repository` key.
4. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) unconditionally creates a `Status` on `commit.stack_id` via `add_status`, with no organization check anywhere in the call chain.

Attacker request: `POST /webhooks` with `X-Github-Event: status`, `X-Hub-Signature` computed over the body using OrgA's `webhook_secret`, and body `{"repository":{"owner":{"login":"OrgA"}}, "sha":"<OrgB's commit sha>", "state":"success", "context":"ci/required-check"}`. The sha is learnable from OrgB's public commit history/PRs. This bypasses `verify_signature` entirely as designed (OrgA is a legitimate, correctly-signing org) and lands on OrgB's commit due to the global, unscoped `Commit.where(sha:)` query.

### Impact Explanation
A payload signed by one tenant (OrgA) writes a `Status` row on another tenant's (OrgB's) `Commit`, satisfying the "payload for one repository mutating another's ... commit" Critical category. If OrgB's deploy pipeline gates on required-status checks matching `context` (a common Shipit configuration, see `Stack#required_statuses`/`blocking_statuses` referenced via `Commit#deployable?` at `app/models/shipit/commit.rb:227-229`), the forged `success` status can make an otherwise-unverified commit `deployable?`, contributing to an unauthorized deploy. This is repeatable against any org whose commit shas are known and any org that owns a valid Shipit `webhook_secret` — the attack only requires control of one legitimately connected org, and any target org with a known commit sha.

### Likelihood Explanation
Preconditions are modest: attacker must run/own one Shipit-connected GitHub organization (to obtain a valid `webhook_secret` for HMAC signing) — this is achievable by any developer who can register a GitHub org and connect it to a shared or multi-tenant Shipit instance, or in single/shared-secret configurations, is automatic. Target commit shas are typically public. No GitHub App private key, session, or API token is needed — only the standard webhook signing already available to a connected org. This is a low-cost, fully repeatable forgery against arbitrary shas.

### Recommendation
In `StatusHandler`, require `repository.full_name` in the `params` schema and scope the commit lookup through `stacks` (as `Handler#stacks` already provides via `Repository.from_github_repo_name(repository_name)`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join `Commit` through `Stack`/`Repository` matching the verified `repository_owner`/`full_name`, rejecting any commit whose stack's repository does not match the payload's repository.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, no live GitHub required):
```ruby
test "status webhook does not create a status on a commit belonging to a different repository" do
  org_b_stack = shipit_stacks(:shipit) # repository owned by "org-b/repo"
  commit = org_b_stack.commits.create!(sha: 'deadbeef' * 5, ...)

  payload = {
    'sha' => commit.sha,
    'state' => 'success',
    'context' => 'ci/required-check',
    'repository' => { 'full_name' => 'org-a/other-repo', 'owner' => { 'login' => 'org-a' } }
  }

  assert_no_difference -> { commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Both sides of the binding to assert: `commit.stack.repository.full_name` ("org-b/repo") vs. `payload.dig('repository','full_name')` ("org-a/other-repo") — before the fix these differ yet a `Status` is still created (test fails against current code, confirming the divergence); after the fix, `commit.statuses.count` must remain unchanged. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
