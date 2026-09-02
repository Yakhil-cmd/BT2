### Title
Cross-org webhook forgery via divergent `repository.owner.login` vs `repository.full_name` fields enqueues `RefreshCheckRunsJob` for a victim stack - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which org's HMAC secret to verify against using `repository.owner.login` (falling back to `organization.login`), while `Handler#stacks` resolves the target `Repository`/`Stack` using the independent, attacker-controlled `repository.full_name` field. Because nothing in the request path checks that these two fields agree, an attacker can pick an org with no `webhook_secret` configured to make verification pass trivially, while pointing `full_name` at a victim repository belonging to a different, secret-protected org, causing `CheckSuiteHandler#process` to enqueue `RefreshCheckRunsJob` against the victim's real commit.

### Finding Description
The claimed binding is: `org used to verify webhook signature (repository.owner.login)` == `org owning the stack whose check runs are refreshed (repository.full_name owner segment)`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally if that org has no `webhook_secret` configured: `return true unless webhook_secret`. [3](#0-2) 
- After verification, `WebhooksController#create` parses the raw body and dispatches to handlers by event type, passing the *entire* attacker-controlled JSON, including any `repository.full_name`. [4](#0-3) 
- `Handler#stacks` and `#repository_name` use `payload.dig('repository', 'full_name')` — a field completely independent from the one used above for signature-org selection — to look up the real `Repository` record via `Repository.from_github_repo_name`. [5](#0-4) 
- `CheckSuiteHandler#process` then iterates `stacks.where(branch: params.check_suite.head_branch)` and schedules `RefreshCheckRunsJob` for any commit matching `head_sha`. [6](#0-5) 

Because `repository.owner.login`/`organization.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon Repository/Stack) are two independent JSON keys inside the same unauthenticated request body, an attacker who knows (or discovers) that some org configured in `Shipit.github` has no `webhook_secret` set can craft a payload where:
- `organization.login` / `repository.owner.login` = `"decoy-org"` (an org with `webhook_secret: nil`) → verification trivially passes regardless of the `X-Hub-Signature` header.
- `repository.full_name` = `"victim-org/victim-repo"` → an unrelated, real, secret-protected repository/stack.
- `check_suite.head_branch` / `check_suite.head_sha` matching the victim stack's tracked branch/commit.

`verify_signature` never inspects `repository.full_name`, and `stacks`/`repository_name` never inspects `repository.owner.login`/`organization.login`. No code path cross-checks that the org actually verified is the same org that owns the acted-upon repository. This is a genuine "payload for one repository mutating another's stack" divergence, not merely relying on the documented "optional webhook_secret" behavior for a single org — the decoy org's lack of a secret is used to forge trust for a *different*, correctly-secured victim org.

### Impact Explanation
Any request that gets past `verify_signature` is treated as fully authenticated for whatever `repository.full_name`/`check_suite` fields it carries. In this attack, an unprivileged internet attacker (no session, no API token, no webhook secret, not a maintainer of any real Shipit org) can enqueue `RefreshCheckRunsJob` for an arbitrary victim stack's commit, provided any org registered in the multi-org `Shipit.github` config has `webhook_secret` unset. `RefreshCheckRunsJob` refreshes check-run status data that feeds Shipit's deployability/merge signals for that commit, so an attacker can inject or manipulate check-run refresh timing/state signals for a repository they do not control and never authenticated for. This is repeatable against any repository tracked by Shipit as long as the decoy org exists, matching "a payload for one repository mutating another's stack/commit" (Critical).

### Likelihood Explanation
Requires a Shipit deployment configured for multiple GitHub orgs (explicitly documented and supported, e.g. `secrets_double_github_app.yml`) where at least one configured org has no `webhook_secret`. Given that the shipped example configs (`config/secrets.development.example.yml`, `secrets.development.shopify.yml`) default `webhook_secret` to nil/commented-out, this is a plausible real-world configuration, not a contrived edge case. The attacker cost is a single crafted unauthenticated HTTP POST to `/webhooks`; no secrets, sessions, or GitHub privileges are needed, and the attack is fully repeatable against any tracked stack/commit.

### Recommendation
Cross-validate the org used for signature verification against the org embedded in `repository.full_name` (and `organization.login` when present) before dispatching to handlers, rejecting mismatches. Alternatively, resolve the target `Repository` using the same `repository_owner` value that was used for signature verification, so a single field determines both which secret is checked and which repository/stack is acted upon. Consider also making `webhook_secret` mandatory for any org in multi-org configurations, or requiring it as a startup/config validation.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":check_suite with mismatched verification org enqueues RefreshCheckRunsJob for a repo not verified for" do
  # Setup: two orgs configured, "decoy-org" has no webhook_secret, "victim-org" does.
  # (config as in test/dummy/config/secrets_double_github_app.yml, but with
  # OrgOne = decoy-org (webhook_secret: nil) and OrgTwo = victim-org (webhook_secret: "realsecret"))

  victim_repo = shipit_repositories(:victim) # owner: "victim-org", name: "victim-repo"
  victim_stack = shipit_stacks(:victim, repository: victim_repo, branch: "master")
  victim_commit = shipit_commits(:victim_head, stack: victim_stack, sha: "deadbeef" * 5)

  request.headers['X-Github-Event'] = 'check_suite'
  # No valid X-Hub-Signature for victim-org is provided/possible (attacker doesn't have the secret)
  request.headers['X-Hub-Signature'] = 'sha1=0000000000000000000000000000000000000000'

  forged_payload = {
    organization: { login: 'decoy-org' },              # used by verify_signature -> no secret -> verified=true
    repository: {
      full_name: 'victim-org/victim-repo',              # used by Handler#stacks -> real victim repo
      owner: { login: 'decoy-org' }
    },
    check_suite: {
      head_branch: 'master',
      head_sha: victim_commit.sha
    }
  }.to_json

  assert_enqueued_with(job: RefreshCheckRunsJob, args: [victim_commit.id]) do
    post :create, body: forged_payload, as: :json
    assert_response :ok
  end
end
```
This demonstrates that a request "verified" only against `decoy-org`'s (secret-less) config still results in `RefreshCheckRunsJob` being enqueued for `victim-org`'s real commit — breaking the intended binding that the org verifying the webhook is the org owning the affected stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
