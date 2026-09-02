### Title
Webhook `repository.owner.login` used for signature verification diverges from `repository.full_name` used for stack lookup, allowing cross-organization `RefreshCheckRunsJob` enqueue - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC against using `params.dig('repository','owner','login')` [1](#0-0) , while `CheckSuiteHandler#process` resolves the target `stacks`/`Repository` for the payload independently, based on the repository identity embedded elsewhere in the same attacker-supplied JSON body [2](#0-1) . Because the raw POST body is entirely attacker-controlled (an unprivileged internet user can `POST /webhooks` directly), the two fields can be set inconsistently: `repository.owner.login = "AttackerOrg"` (to pass signature verification with a secret the attacker legitimately knows) while the repository/stack-resolving field references a victim organization's repository.

### Finding Description
The binding under test is: `verifying_org` (the org whose `webhook_secret` produced a valid HMAC) `==` `target_stack.repository.owner` (the org whose `Commit`/`Stack` receives the enqueued `RefreshCheckRunsJob`).

Trace:
1. `WebhooksController#create` parses the raw JSON body with `JSON.parse(request.raw_post)` and dispatches to handlers only after `verify_signature` passes [3](#0-2) .
2. `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (or the top-level `organization.login` fallback), fetches `Shipit.github(organization: repository_owner)`, and verifies the HMAC using **that org's** `webhook_secret` [4](#0-3) , [1](#0-0) .
3. `Shipit.github` looks up per-organization config from `secrets.github` keyed by the (attacker-supplied) organization string [5](#0-4) , and `GitHubApp#verify_webhook_signature` does a straightforward HMAC-SHA1 compare against that org's `webhook_secret` [6](#0-5) .
4. Once verification passes, `CheckSuiteHandler#process` queries `stacks.where(branch: params.check_suite.head_branch)` and `stack.commits.where(sha: params.check_suite.head_sha)`, enqueuing `schedule_refresh_check_runs!` (which enqueues `RefreshCheckRunsJob`) [7](#0-6) . This handler's own `params` schema only requires `check_suite.head_sha`/`head_branch` — it never re-validates that the resolved `stacks` scope belongs to the same organization that was used for signature verification [8](#0-7) .

The root cause is that the org identity used to select the verification secret (`repository.owner.login`) and the repository identity used to select the target `stacks` scope are read from two independently attacker-controlled locations in the same self-crafted JSON body, with no code path that cross-checks them against each other. An attacker who administers a real GitHub organization "AttackerOrg" with a Shipit-configured webhook (knows `AttackerOrg`'s `webhook_secret` legitimately) can build a `check_suite` JSON payload where `repository.owner.login` is `"AttackerOrg"` (so `verify_signature` picks AttackerOrg's secret and the HMAC — computed by the attacker using their own known secret — passes) but the handler's repository/stack resolution ends up pointing at a victim organization's onboarded `Stack`/`Commit` (matching branch name and an existing, publicly-visible commit SHA on the victim's repo). None of `verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema on `CheckSuiteHandler`, or model validations enforce that the two repository-owner references agree, because the schema never declares/validates a `repository` key at all.

### Impact Explanation
A successful exploit causes `Shipit::RefreshCheckRunsJob` to be enqueued and executed against a `Commit`/`Stack` belonging to an organization the attacker never authenticated as, i.e., "a payload for one repository mutating another's stack, commit, task or team." This can pollute or force refresh of `CheckRun` state for a victim's commit using the Shipit-side GitHub App credentials for that victim org, which can influence deploy-gating decisions (whether a commit is considered "green" and deployable) — a cross-tenant integrity break. It is repeatable against any organization's stack whose repository name and an in-scope branch/commit SHA the attacker can guess or observe (commit SHAs and branch names are public GitHub data), independent of the attacker's own org boundary.

### Likelihood Explanation
Preconditions: the attacker needs their own legitimate GitHub organization with a Shipit-configured GitHub App/webhook (a normal customer configuration, not a privileged Shipit role), and must know that org's own `webhook_secret` (which they configured themselves) — no victim or Shipit secret is required. They need to know a victim `Stack`'s `branch` and an existing `Commit#sha`, both of which are public GitHub metadata for any repo they can view. The attack requires only a single crafted HTTP POST to `/webhooks` with a self-signed payload; it is directly repeatable against any stack in the Shipit instance.

### Recommendation
In `WebhooksController#verify_signature` and/or in each `Handler`, cross-validate that the repository/organization used to select the verifying `webhook_secret` matches the repository/organization actually used to resolve `stacks`/`Repository` records for that payload (e.g., require and validate a single canonical `repository.full_name`/`repository.owner.login` pair via the `ExplicitParameters` schema shared by all handlers, and reject the request if the value used for signature-org lookup doesn't equal the value used for stack resolution).

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/check_suite_handler_test.rb`, no live GitHub):
1. Configure two orgs in test secrets, `"attacker-org"` with `webhook_secret: "attacker-secret"` and `"victim-org"` with `webhook_secret: "victim-secret"`.
2. Create a victim `Stack` (`repository.owner == "victim-org"`) with a `Commit` (`sha: "deadbeef", branch: "main"`).
3. Build a `check_suite` payload body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/repo"}, "check_suite": {"head_sha": "deadbeef", "head_branch": "main"}}`.
4. Sign it with `OpenSSL::HMAC.hexdigest('sha1', "attacker-secret", body)` and `POST /webhooks` with `X-Hub-Signature: "sha1=<sig>"`, `X-Github-Event: "check_suite"`.
5. Assert response is `200`/`204` (signature accepted) — proving `verify_signature` passed using `attacker-org`'s secret while the payload's stack-resolving repository is `victim-org`.
6. Assert `RefreshCheckRunsJob` was enqueued with args resolving to the victim `Commit`, i.e. assert `enqueued_jobs` job args' commit `.stack.repository.owner == "victim-org"`, while the verifying org (`Shipit.github(organization: "attacker-org")`) `!= "victim-org"` — demonstrating `verifying_org ("attacker-org") != target_stack.repository.owner ("victim-org")`, breaking the claimed binding.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L7-12)
```ruby
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
