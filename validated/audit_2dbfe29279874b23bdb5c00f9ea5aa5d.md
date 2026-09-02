### Title
Webhook signature verification is keyed off an attacker-controlled field decoupled from the field handlers use to select target repositories/commits, and `StatusHandler` performs zero repository scoping - allowing cross-tenant commit-status forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify against using `params.dig('repository','owner','login')`, a value taken from the unauthenticated JSON body itself, while every `Handler` subclass (including `PushHandler` and `StatusHandler`) resolves the actual target `Repository`/`Commit` from a *different* field in that same body (`repository.full_name`, or in `StatusHandler`'s case just a bare `sha` with no repository field at all). No code anywhere checks that the org used to pass signature verification actually owns the repository/commit being mutated. Combined with `GitHubApp#verify_webhook_signature` returning `true` unconditionally when no `webhook_secret` is configured for the org named in the payload, an attacker who can reach `POST /webhooks` can pick an org that has no configured secret (or an org whose secret they legitimately hold for their own onboarded repo) to pass `verify_signature`, then supply an arbitrary `repository.full_name` (for `push`) or an arbitrary `sha` (for `status`, which isn't even repo-scoped) belonging to a completely unrelated victim stack.

### Finding Description
The binding the question implicitly requires is: `org_that_verified_signature == org_that_owns_the_mutated_repository/commit`. Tracing the code shows this equality is never enforced.

- `WebhooksController#verify_signature` computes `repository_owner` purely from the attacker-supplied JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) , then does `github_app = Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature(...)` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that org has no `webhook_secret` configured: `return true unless webhook_secret` [3](#0-2) . `Shipit.github_app_config` resolves per-org config by downcasing the org key from `secrets.github` [4](#0-3) , and `Shipit.github` raises `GithubOrganizationUnknown` only if the org isn't present at all, not if it lacks a secret [5](#0-4) .
- Once verification passes, `Handler#repository_name` reads `payload.dig('repository', 'full_name')` - a field completely independent from `repository_owner` used above - to resolve `stacks` via `Repository.from_github_repo_name(repository_name)` [6](#0-5) . `PushHandler#process` uses this to call `stack.sync_github(expected_head_sha: params.after)` on any stack matching that (attacker-chosen) repo/branch [7](#0-6) .
- `StatusHandler#process` is worse: it does not even read `repository.full_name`. It does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [8](#0-7) , which is a global, unscoped lookup across every stack/repository in the entire Shipit instance matching that sha.

Exploit flow: an attacker who owns/controls an org onboarded into this multitenant Shipit instance (or who finds an org entry with no `webhook_secret` configured) crafts two raw POSTs to `/webhooks`:
1. `X-Github-Event: push` with `repository.owner.login` = attacker's/no-secret org (to pass `verify_signature`) and `repository.full_name` / `ref` = the victim's repo/branch. This queues `GithubSyncJob` against the victim's real `Stack`.
2. `X-Github-Event: status` with `sha` = a known victim commit sha and `state: success`. Because `StatusHandler` never checks `repository`, this same forged, cross-org-verified request flips the CI status of the victim's commit via `Commit#create_status_from_github!`.

Existing guards do not stop this: `drop_unhandled_event` only checks the event name is registered; `verify_signature` only checks *some* org's secret matches, never that the org matches the payload's actual repository; `ExplicitParameters` schemas for `PushHandler`/`StatusHandler` validate presence/type of fields but not their relationship to the verifying org; there is no `Repository`/`Stack` ownership check at all in `StatusHandler`.

### Impact Explanation
An attacker can flip `Commit#status`-derived CI state for any commit sha in the system, on any tenant's stack, using only an org/secret pairing they legitimately possess for their own unrelated repo (or a misconfigured no-secret org entry), which is exactly the "payload for one repository mutating another's stack, commit" Critical impact category. If a stack's `deployable?` gate depends on the commit's aggregated CI status, this can be used to make an unreviewed/unwanted commit appear deployable, unblocking deploys. This is repeatable against arbitrary shas/repositories with no rate limiting beyond the request itself, and the blast radius spans every tenant/stack hosted on the same Shipit instance, not just the attacker's own repository.

### Likelihood Explanation
Exploitability hinges on the attacker being able to pass `verify_signature` for *some* org while targeting a different repository. Two paths satisfy this: (a) the operator configured an org in `secrets.github` with no `webhook_secret` at all (misconfiguration that the code silently tolerates rather than rejects), or (b) the attacker legitimately onboarded their own repository/org into the shared multi-tenant instance and thus knows its real `webhook_secret`, then reuses that valid signature while spoofing `repository.full_name`/`sha` for a victim. Path (b) requires no special privilege beyond being a normal onboarded tenant of a multi-org Shipit deployment, which is a realistic and low-cost precondition; path (a) requires an operator misconfiguration. `StatusHandler`'s complete lack of repository scoping means path (b) alone is sufficient for the status-flip half of the chain, independent of whether a no-secret org exists.

### Recommendation
Enforce the binding explicitly: after verifying the signature against `repository_owner`'s secret, require that the repository/commit being mutated actually belongs to that same verified organization before performing any write. Concretely: reject requests where an org's `webhook_secret` is unset (fail closed instead of `return true unless webhook_secret`), and add a repository-ownership check inside `Handler#stacks`/`StatusHandler#process` (e.g., scope `Commit.where(sha:)` through `stacks` derived from the *verified* organization, not merely by matching sha, and cross-check `payload.dig('repository','owner','login')` used for verification equals the owner of `repository.full_name`).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (added test)
test "status webhook verified via a different org can flip an unrelated commit's status" do
  victim_commit = shipit_commits(:first) # belongs to stack whose repo is verified by org "shopify"

  # Attacker's own org, onboarded separately, with a secret the attacker knows.
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true) # simulates either a no-secret org or attacker's own valid signature
  )

  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'attacker-org' }, 'full_name' => 'attacker/unrelated-repo' }
  }.to_json

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body:, as: :json
  end

  assert_equal 'success', victim_commit.reload.status
end
```
Assert on both sides of the binding: `repository_owner` used for verification (`attacker-org`) versus the actual owner of `victim_commit.stack.repository.full_name` - showing they differ yet the write still succeeds, proving the equality the system should enforce is violated.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
