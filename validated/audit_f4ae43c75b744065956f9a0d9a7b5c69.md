### Title
Cross-tenant status mutation via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits purely by `sha`, with no filter on the webhook's originating repository, while every other webhook handler in this engine scopes mutations through the `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`). Because git commit SHAs are content hashes shared naturally across forks/mirrors of the same history, a single validly-signed webhook from one organization's repository can write a `Status` onto commits belonging to unrelated stacks/repositories/tenants.

### Finding Description
The broken binding is: `webhook.repository_owner/repository.full_name == commit.stack.repository` must hold for any record mutated by processing that webhook. `StatusHandler#process` violates this: [1](#0-0) 

It calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no `stack_id`/repository filter, in contrast to the base `Handler` class which explicitly provides a `stacks` scoping helper for this exact purpose: [2](#0-1) 

`verify_signature` in `WebhooksController` only authenticates that a payload was HMAC-signed with the secret configured for the organization named in `payload['repository']['owner']['login']` — it proves *origin*, not *scope*: [3](#0-2) 

`GitHubApp#verify_webhook_signature` confirms only that the raw body matches that organization's `webhook_secret`; it says nothing about which `Commit`/`Stack` rows may be touched: [4](#0-3) 

Since `Commit#sha` is a git SHA-1 of tree+parents+metadata, any fork/mirror that shares ancestor history with a victim repository will contain commits with byte-identical SHAs — no cryptographic collision is required. If an attacker's own repository (legitimately onboarded as a separate Shipit stack, with its own valid, org-scoped GitHub webhook secret) shares any commit SHA with a victim stack (e.g., a shared upstream commit, a common initial commit, or a forked/mirrored history), a real GitHub-signed `status` event for the attacker's own repository will cause `Commit.where(sha: ...)` to match and mutate the victim's `Commit`/`Status` rows too, via `create_status_from_github!`, which affects `Status::Group`, deploy-blocking logic (`Commit#blocked?`, `deployable?`), and can trigger `stack.schedule_merges` for a stack the attacker never authenticated against.

None of the existing guards prevent this: `verify_signature` is organization-scoped, not per-commit/stack; `drop_unhandled_event` only checks event type; the `ExplicitParameters` schema in `status_handler.rb` validates field shape (`sha`, `state`, etc.) but has no repository constraint; and the `stacks` helper that would fix this is defined in `Handler` but simply never invoked by `StatusHandler`.

### Impact Explanation
A single verified webhook for repository/org A can write a `Status` record (and downstream side effects: `Hook.emit(:commit_status/:deployable_status)`, `stack.schedule_merges`) onto commits belonging to stacks in unrelated repositories/orgs B, C, … that happen to share the SHA — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius is one-to-many: one forged/legitimate webhook from a single authenticated tenant can flip CI status, unblock deploys, or trigger continuous-delivery/merge scheduling for every stack across the installation that contains a `Commit` row with that SHA, regardless of tenant boundary.

### Likelihood Explanation
Exploitation requires: (1) the attacker's own repository is already onboarded as a Shipit stack with its own legitimately configured GitHub App/webhook secret (a normal, unprivileged setup step in a multi-tenant Shipit deployment), and (2) a SHA collision with a victim stack's commit — realistically achievable via forks/mirrors that share commit ancestry, not brute-force hash collision. This is plausible in any Shipit instance hosting multiple stacks that are forks/mirrors of each other or share a common upstream. The attacker's cost is minimal (push/merge a shared-history commit and let GitHub emit a normal status webhook); no secrets are needed beyond the ones GitHub itself computes for the attacker's own onboarded repository.

### Recommendation
Scope `StatusHandler#process` the same way other handlers are expected to via `Handler#stacks`: restrict `Commit.where(sha: params.sha)` to `stacks.flat_map(&:commits)` (or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) so only commits belonging to the stacks that map to the webhook's `repository.full_name` can be mutated.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "a status webhook for one repository does not mutate commits in unrelated stacks" do
  sha = "a" * 40

  stack_a = shipit_stacks(:shipit)               # repository X
  stack_b = create_stack(repository_full_name: "other-org/other-repo")
  stack_c = create_stack(repository_full_name: "third-org/third-repo")

  commit_a = stack_a.commits.create!(sha: sha, message: "shared ancestor")
  commit_b = stack_b.commits.create!(sha: sha, message: "shared ancestor")
  commit_c = stack_c.commits.create!(sha: sha, message: "shared ancestor")

  payload = {
    'sha' => sha,
    'state' => 'success',
    'repository' => { 'full_name' => stack_a.github_repo_name }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # Binding under test: only commit_a's stack (the webhook's own repository) should be mutated.
  assert_equal 1, Status.where(commit_id: [commit_a.id, commit_b.id, commit_c.id]).count
  assert_equal [stack_a.id], Status.where(commit_id: [commit_a.id, commit_b.id, commit_c.id]).pluck(:stack_id).uniq
end
```
Current behavior produces `Status.where(...).count == 3` across `stack_a`, `stack_b`, `stack_c`, confirming the cross-tenant mutation described above.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
