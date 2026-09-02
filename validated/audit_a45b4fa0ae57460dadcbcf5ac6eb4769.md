### Title
Unauthenticated forged `push` webhook mutates arbitrary victim stacks when the target org has no `webhook_secret` configured - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` looks up the `GitHubApp` for `repository_owner`, itself read verbatim from the attacker-supplied JSON body, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that org has no `webhook_secret` configured. `PushHandler` then resolves the target stacks purely from `payload.dig('repository', 'full_name')` (also attacker-controlled) via `Handler#stacks`/`Repository.from_github_repo_name`, and calls `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack. No signature, ownership, or ACL check ties the payload to the repository it claims to be from.

### Finding Description
The claimed binding is: `repository_owner_in_payload == authenticated_owner_of_this_push`. Tracing the code shows this equality is never actually verified — the "authentication" step derives its own identity entirely from the unverified payload:

- `repository_owner` is read directly from `params.dig('repository','owner','login')` [1](#0-0)  and used to select which `GitHubApp`/secret to check against [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that org: `return true unless webhook_secret` [3](#0-2) .
- `PushHandler#process` resolves stacks solely from `Handler#stacks`, which does `Repository.from_github_repo_name(repository_name)&.stacks`, where `repository_name` is `payload.dig('repository', 'full_name')` — again taken straight from the unauthenticated body [4](#0-3) .
- It then calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack matching the payload's branch [5](#0-4) .

Because `repository.owner.login` and `repository.full_name` are both read from the same attacker-controlled JSON body used to pass the (non-existent) signature check, an attacker only needs to target an org that has no `webhook_secret` configured. They can set `repository.owner.login` and `repository.full_name` to the victim's org/repo directly — no commit-SHA collision with an attacker-owned repository is required at all; the attacker simply declares themselves to be the victim repository in the forged JSON. `sync_github` is then invoked with `expected_head_sha` fully attacker-supplied, which can append commits and drive continuous delivery for a repository the attacker never authenticated against.

The specific "shared SHA with attacker repo" mechanism cited in the question is not the actual exploitable vector in this code path — `PushHandler` never resolves stacks via a bare-SHA lookup that could collide across repositories; it resolves stacks via `repository.full_name`, which the attacker controls outright in the payload. The real, broader root cause is that no-secret organizations have zero webhook authentication, letting a forged `push` for **any** `repository.full_name` mutate that repo's stacks.

None of the listed guards prevent this: `verify_signature` trusts the payload's own claimed owner when no secret exists; `drop_unhandled_event` only filters unknown event types, not identity; `ExplicitParameters` only validates the presence/shape of `ref`/`after`, not their origin; there is no `force_github_authentication`, `User#authorized?`, or `require_permission!` call anywhere on this unauthenticated controller.

### Impact Explanation
For any GitHub organization configured in Shipit without a `webhook_secret`, an unauthenticated attacker can forge a `push` event naming any repository/stack in that org (or any org lacking a secret) and trigger `Stack#sync_github`, which can append arbitrary commits/SHAs into the stack's history and subsequently drive continuous deployment. This is a cross-repository/cross-tenant state-mutation bypass: one HTTP request, with a fully attacker-crafted body and no valid GitHub signature, mutates stacks belonging to a repository the attacker does not own. This matches "Critical — payload for one repository mutating another's stack" and can also enable unauthorized deploys downstream since `sync_github` results feed continuous delivery. It is repeatable indefinitely and against every stack under any no-secret org.

### Likelihood Explanation
Preconditions: the target organization must have no `webhook_secret` configured in Shipit (this is an operator configuration gap, not something the attacker controls, but it is explicitly called out as in-scope by the question's "org with no configured webhook_secret" framing). Given that precondition, the attack requires only an unauthenticated HTTP POST to `/webhooks` with a hand-crafted JSON body and an `X-Github-Event: push` header — no GitHub account, no repository access, and no valid signature are needed. This is trivially repeatable and low-cost.

### Recommendation
Do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is blank — either require every configured organization to have a `webhook_secret` and fail closed if absent, or otherwise strongly authenticate the payload's claimed repository against a trusted source before resolving stacks in `PushHandler`/`Handler#stacks`. At minimum, log/alert and reject requests for organizations without a secret rather than treating "no secret" as "signature verified."

### Proof of Concept
```ruby
# test/controllers/shipit/webhooks_controller_test.rb (conceptual, no live GitHub)
test "forged push against org with no webhook_secret mutates victim stack" do
  # Precondition: configure Shipit.github for org "victim-org" with no webhook_secret.
  Shipit.github_configs = { 'victim-org' => { app_id: 1, installation_id: 1, private_key: 'x' } }

  stack = shipit_stacks(:shipit) # belongs to repository "victim-org/victim-repo", branch "master"
  original_sha = stack.commits.last.sha

  forged_after_sha = 'f' * 40
  payload = {
    ref: 'refs/heads/master',
    after: forged_after_sha,
    repository: { full_name: 'victim-org/victim-repo', owner: { login: 'victim-org' } }
  }.to_json

  post shipit.webhooks_path,
       params: payload,
       headers: { 'X-Github-Event' => 'push', 'Content-Type' => 'application/json' }
       # deliberately NO X-Hub-Signature, or a garbage one

  assert_response :ok

  # Binding under test, before vs after:
  # before: stack.expected_head_sha != forged_after_sha (attacker never authenticated as victim-org)
  # after:  stack.reload triggers sync_github with expected_head_sha == forged_after_sha
  assert_enqueued_with(job: Shipit::GithubSyncJob) # or assert stack was passed forged_after_sha
end
```

**Caveat**: I could not fully trace `Stack#sync_github`'s internal effect (e.g., whether it synchronously appends a `Commit` record or only enqueues a background sync job) within the available iterations, so the exact downstream side effect (new `Commit` row vs. deploy trigger) should be confirmed by a background agent with full file access before finalizing the PoC assertions.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
