### Title
Check-suite webhook signature is verified against `repository.owner.login`, but the stack/commit lookup trusts the independent, unvalidated `repository.full_name` from the same body, letting a signature valid for one org drive check-run refresh scheduling on any other org's stack - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check using `repository.owner.login` (or `organization.login`) pulled straight from the JSON body, and `GitHubApp#verify_webhook_signature` returns `true` outright when that org has no `webhook_secret` configured. Independently, `Handlers::Handler#stacks` (used by `CheckSuiteHandler#process`) resolves the target `Repository`/`Stack` using `repository.full_name` from the very same unsigned body, with no check that its owner segment matches the org that was used to verify the signature.

### Finding Description
The binding that should hold is: `organization_used_to_verify_signature (repository_owner from payload) == owner(repository.full_name used to resolve stacks)`. This binding is never enforced.

- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is blank/unset (`return true unless webhook_secret`), a documented, legitimate configuration state per `config/secrets.development.example.yml` and `docs/setup.md` ("webhook_secret: # nil"). [2](#0-1) 
- `Handler#stacks`, used by `CheckSuiteHandler#process`, resolves the affected repository/stack via `payload.dig('repository', 'full_name')`, a field that is never re-checked against `repository_owner` above. [3](#0-2) 
- `Repository.from_github_repo_name` simply splits `full_name` on `/` and does a plain `find_by(owner:, name:)` lookup with no cross-check to the verified org. [4](#0-3) 
- `CheckSuiteHandler#process` then iterates `stacks.where(branch: ...)` and calls `stack.commits.where(sha: ...).each(&:schedule_refresh_check_runs!)`, which enqueues `RefreshCheckRunsJob` against those commits. [5](#0-4) 
- `CheckSuiteHandler`'s `ExplicitParameters` schema only requires `check_suite.head_sha` and `check_suite.head_branch`; it does not require or constrain `repository` at all, so nothing in the handler layer validates `repository.full_name` against the verified org. [6](#0-5) 

Exploit flow: attacker POSTs to `/webhooks` with `X-Github-Event: check_suite` and a body where `repository.owner.login` = `attacker-org` (an org that is configured on this multi-tenant Shipit instance but has no `webhook_secret` set, or whose secret the attacker legitimately knows), `repository.full_name` = `victim-org/prod-repo`, `check_suite.head_branch` = `main`, `check_suite.head_sha` = a real commit sha tracked by the victim's stack. `verify_signature` passes because it only checks the signature against `attacker-org`'s (nil) secret. Dispatch proceeds to `CheckSuiteHandler#process`, which resolves `victim-org/prod-repo`'s stack purely from the body and schedules `RefreshCheckRunsJob` for the victim's commit.

Existing guards do not close this gap: `verify_signature` only proves the payload's HMAC matches *the org selected by the same untrusted payload*, it never confirms `repository.full_name`'s owner equals that org; `drop_unhandled_event` and the `ExplicitParameters` schema for `CheckSuiteHandler` don't touch `repository` at all; `Repository.from_github_repo_name` and `Stack` validations only validate name-format constraints, not cross-tenant ownership.

### Impact Explanation
An attacker who controls (or whose configured org has no configured `webhook_secret` for) any org onboarded to a multi-tenant Shipit instance can trigger `RefreshCheckRunsJob`-style side effects (`Commit#schedule_refresh_check_runs!` → `RefreshCheckRunsJob.perform_later`) against an arbitrary victim org's stack/commit, without ever authenticating as that victim org. This is a "payload for one repository mutating another's stack/commit" case (Critical per the rubric). It is fully repeatable per request against any repository/stack/commit combination the attacker can guess or discover (repo full names and commit SHAs are typically public), and the blast radius spans every tenant configured on the same Shipit host since the org-selection for signature verification is entirely payload-driven and decoupled from the resolved target repository.

### Likelihood Explanation
This requires: (1) the Shipit deployment to use the multi-org GitHub config schema (`Shipit.github(organization:)` keyed lookup, per `lib/shipit.rb#github_app_config`), and (2) at least one onboarded org to have `webhook_secret` unset — an explicitly supported, documented configuration (`webhook_secret: # nil` in `docs/setup.md` and the example secrets files). Given that, the attacker's cost is a single unauthenticated HTTP POST with attacker-chosen JSON, no GitHub credentials, no Shipit session, and no knowledge of any real secret. This is trivially repeatable and requires no timing or race conditions.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handlers::Handler`), after determining `repository_owner` used to select the verifying GitHub App/secret, require that `payload.dig('repository', 'full_name')`'s owner segment equals `repository_owner` (case-insensitively) before dispatching to any handler; reject (422) on mismatch. Additionally, treat a missing/blank `webhook_secret` as "verification required but not configured" (fail closed, e.g. 422) rather than silently returning `true` in `GitHubApp#verify_webhook_signature`, unless explicit auth-disabled/testing mode is set.

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb`):
```ruby
test ":check_suite forged owner cannot schedule refresh for another org's stack" do
  # Setup: two orgs configured, "attacker-org" with no webhook_secret, "victim-org" owning @stack's repository.
  victim_commit = shipit_commits(:first)
  victim_repo_full_name = victim_commit.stack.github_repo_name # e.g. "victim-org/prod-repo"

  body = {
    action: 'requested',
    check_suite: { head_branch: victim_commit.stack.branch, head_sha: victim_commit.sha },
    repository: { full_name: victim_repo_full_name, owner: { login: 'attacker-org' } }
  }.to_json

  request.headers['X-Github-Event'] = 'check_suite'
  # No X-Hub-Signature needed because attacker-org has no webhook_secret configured,
  # so GitHubApp#verify_webhook_signature short-circuits to true.

  # BEFORE: assert repository_owner('attacker-org') != owner(victim_repo_full_name) == 'victim-org'
  assert_not_equal 'attacker-org', victim_repo_full_name.split('/').first

  assert_enqueued_with(job: RefreshCheckRunsJob, args: [commit_id: victim_commit.id]) do
    post :create, body:, as: :json
    assert_response :ok
  end
  # AFTER (post-fix expectation): request should be rejected (422) because
  # repository.owner.login ('attacker-org') != owner(repository.full_name) ('victim-org'),
  # and RefreshCheckRunsJob must NOT be enqueued for victim_commit.
end
```
This demonstrates the divergence: the org used to pass signature verification (`attacker-org`) does not equal the org owning the mutated stack/commit (`victim-org`), yet the job is enqueued.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
