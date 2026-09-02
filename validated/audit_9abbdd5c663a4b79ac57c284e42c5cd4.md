### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no scoping to the repository or organization that was verified by the webhook signature, `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github! }`. Because the base `Handler` class does provide a `repository_name`/`stacks` scoping helper that `StatusHandler` never uses, a payload verified for organization X's repository can silently mutate the CI status of an unrelated commit belonging to organization Y's stack whenever the two share an identical sha.

### Finding Description
The broken binding is: `verified_org(params) == owning_org(matched_commit)` is assumed but never enforced. In reality `verified_org(params)` is determined solely by `WebhooksController#repository_owner` (`params.dig('repository','owner','login')`) which feeds `Shipit.github(organization: repository_owner)` for signature verification (`app/controllers/shipit/webhooks_controller.rb:24-49`), while `owning_org(matched_commit)` is whatever organization/stack happens to own any `Commit` row with the same `sha` (`app/models/shipit/webhooks/handlers/status_handler.rb:21-23`). Nothing ties the two together.

Concretely:
1. `Handler#initialize` parses the payload into `params` via `ExplicitParameters` (`app/models/shipit/webhooks/handlers/handler.rb:21-24`) — the schema only requires `sha`, `state`, and optional fields; it never validates `repository.full_name` against the commit being updated.
2. `Handler` does define a `stacks`/`repository_name` helper scoped to the payload's `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), but `StatusHandler#process` doesn't use it at all — it queries the global `Commit` table directly by `sha` only [1](#0-0) .
3. `Commit#create_status_from_github!` then unconditionally writes the forged status onto whatever `stack`/`Commit` row matched, regardless of which org's webhook secret verified the request [2](#0-1) .

Additionally, `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization: `return true unless webhook_secret` [3](#0-2) . This means an attacker only needs to target an organization X entry in Shipit's GitHub config that has no `webhook_secret` set (a legitimate, common minimal setup, e.g. GitHub App-based auth without a webhook secret) to pass `verify_signature` trivially, with a payload naming any `repository.owner.login` mapped to org X and any `sha` value. Once verification passes, `StatusHandler` never re-checks that the target commit's repository matches the payload's `repository.full_name` at all — the org that "verified" (X) and the org that owns the mutated `Commit` row (Y) can diverge freely as long as a matching sha exists in Y's stack (e.g., an independently-pushed identical commit, a squashed/rebased duplicate, or a known sha from Y's public history).

Existing guards checked and found insufficient:
- `verify_signature` only proves the payload was accepted for org X's config (or, in the secret-less case, proves nothing).
- `drop_unhandled_event` / `check_if_ping` are irrelevant to this path.
- `ExplicitParameters` schema in `StatusHandler.params` does not require or check `repository.full_name`.
- `Handler#stacks`/`repository_name` exist in the base class but are dead code from `StatusHandler`'s perspective — it never calls them.
- No model validation on `Commit` or `Repository` ties a status update back to the verifying organization.

### Impact Explanation
A payload verified (or trivially accepted due to a missing `webhook_secret`) for organization X can write a forged commit status (`success`, `failure`, etc.) onto a `Commit` row belonging to an entirely different, unrelated stack/repository in organization Y, as long as the shas collide. Since `Commit#deployable?` and CI gating (`blocked?`, `status`) are derived directly from `statuses` populated this way, this can flip deploy-gating checks for org Y's stack — a payload for one repository mutating another's stack/commit, matching the "Critical" impact category explicitly listed in scope. The blast radius spans every tenant/org configured on the same Shipit instance sharing the `Commit` table, and the attack is repeatable per matching sha.

### Likelihood Explanation
Preconditions: (1) the attacker needs at least one Shipit-configured GitHub organization/config entry to accept the webhook — either one where they know/can compute `webhook_secret` (not required if the target org config has no `webhook_secret` set, satisfying the question's "secret-less config" premise), and (2) a matching `sha` must already exist as a `Commit` row under an unrelated org's stack. Colliding shas across unrelated stacks are realistic in practice: identical commits (e.g., common dependency bump commits, cherry-picks, or commits copied/pushed independently across forks/mirrors) frequently share sha across repositories since git shas are content-addressed and repository-independent. No privileged Shipit role, session, or secret from the target organization is required. This is feasible with a single crafted HTTP POST to `/webhooks` with correct headers, making it low-cost and repeatable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any other handler using bare sha-only lookups) to the stacks/repository derived from the verified payload, using the existing `stacks`/`repository_name` helper on `Handler`, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join `Commit` through `Stack`/`Repository` filtered by `payload.dig('repository','full_name')`, so a status update can never cross into a repository the payload didn't name. Separately, treat a missing `webhook_secret` as a configuration error to reject/warn rather than silently authorizing all payloads (`GitHubApp#verify_webhook_signature`).

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "does not update commits belonging to a different repository/org with the same sha" do
  stack_x = shipit_stacks(:shipit) # org X's stack
  repo_y  = Shipit::Repository.create!(owner: 'org-y', name: 'repo-y')
  stack_y = Shipit::Stack.create!(repository: repo_y, environment: 'production')

  shared_sha = 'a' * 40
  commit_x = stack_x.commits.create!(sha: shared_sha, message: 'x')
  commit_y = stack_y.commits.create!(sha: shared_sha, message: 'y')

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci',
    'repository' => { 'full_name' => stack_x.github_repo_name, 'owner' => { 'login' => 'org-x' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert_equal 1, commit_x.reload.statuses.count
  # Vulnerable behavior: commit_y also receives the forged status despite payload never naming org-y/repo-y
  assert_equal 1, commit_y.reload.statuses.count, "unrelated org Y commit should not have been updated by org X's payload"
end
```
This test demonstrates that a status payload naming only org X's repository still mutates org Y's `Commit` row solely because the `sha` values collide, confirming the missing repository/org scoping in `StatusHandler#process`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
