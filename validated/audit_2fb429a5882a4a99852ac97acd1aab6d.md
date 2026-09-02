### Title
Webhook signature verified against attacker-controlled `repository.owner.login`, but repository lookup uses independently attacker-controlled `repository.full_name` — cross-organization `CheckSuiteHandler` write - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify against using `params.dig('repository','owner','login')` from the raw, unauthenticated request body itself, not from any independently verified source. `Handler#stacks` then resolves the target `Repository`/`Stack` using a *different* field from the same body, `params.dig('repository','full_name')`. Because these two fields are never cross-checked, an attacker can pick an org `X` that is configured with no `webhook_secret` (or by using `repository.owner.login = X`) to trivially pass signature verification, while setting `repository.full_name = "Y/real-repo"` so `CheckSuiteHandler#process` acts on victim org `Y`'s real stack/commit.

### Finding Description
The broken binding is: `repository_owner` (used in `Shipit.github(organization: repository_owner)` for signature verification, at [1](#0-0) , sourced from `payload.dig('repository','owner','login')` at [2](#0-1) ) is assumed to equal the organization that owns `repository.full_name` used by `Handler#stacks`/`Repository.from_github_repo_name` at [3](#0-2)  and [4](#0-3) . Nothing in the controller or `Handler` enforces `repository.owner.login == repository.full_name.split('/').first`.

`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's config has no `webhook_secret` set: `return true unless webhook_secret` at [5](#0-4) . The multi-org config schema explicitly supports orgs with `webhook_secret: # nil`, as shown in the documented config and the test fixture (`OrgTwo` has no `webhook_secret`) [6](#0-5)  and [7](#0-6) .

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: check_suite` and no valid `X-Hub-Signature` (or any value), and a JSON body where `repository.owner.login = "OrgTwo"` (attacker's own org, unauthenticated/no secret) but `repository.full_name = "OrgOne/real-repo"` (victim org's real, tracked repository), plus a `check_suite.head_branch`/`check_suite.head_sha` matching a real tracked commit on `OrgOne`'s stack. `verify_signature` computes `Shipit.github(organization: "OrgTwo")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the actual signature header. The request proceeds to `Shipit::Webhooks.for_event('check_suite')` → `CheckSuiteHandler.call(params)` at [8](#0-7) . `CheckSuiteHandler#process` resolves `stacks` via `Repository.from_github_repo_name(repository_name)` where `repository_name` comes from `payload.dig('repository','full_name')` — i.e., `"OrgOne/real-repo"` — completely independent of the org used for signature verification [9](#0-8) . If a stack for `OrgOne/real-repo` has a commit matching `head_sha` on the branch `head_branch`, `schedule_refresh_check_runs!` is invoked, enqueuing `RefreshCheckRunsJob.perform_later(commit_id: id)` [10](#0-9) . When that job runs, it will eventually call `stack.github_api` for `OrgOne`'s repo, which authenticates using `OrgOne`'s own GitHub App token (via `Repository#github_app` → `Shipit.github(organization: owner)` → `GitHubApp#token`) [11](#0-10) , and `Commit#refresh_check_runs!`/`paginated_check_runs` calls `stack.github_api.check_runs(...)` [12](#0-11) .

No existing guard prevents this: `verify_signature` never compares the verifying org to the repository's actual owner; `Handler#stacks` trusts `payload['repository']['full_name']` unconditionally with no cross-check against the org used for authentication; `drop_unhandled_event` and `ExplicitParameters` schema (`requires :head_sha`, `:head_branch`) do not validate ownership consistency either.

### Impact Explanation
An unauthenticated internet attacker who merely knows (a) that an org with a blank `webhook_secret` exists in the Shipit deployment's multi-org GitHub config, and (b) the `owner/repo` full name and a real tracked branch+commit SHA of a *different* victim org's stack, can trigger a job that causes the victim org's own GitHub App credentials to be used to make GitHub API calls (`check_runs`) attributed to the attacker's forged event. This is a cross-repository/cross-tenant write triggered by a payload that never authenticated against the victim org, matching the "payload for one repository mutating another's stack/commit" Critical category. It is repeatable against any repository tracked by Shipit as long as one org in the multi-org config has an empty `webhook_secret`, and it scales to any stack/commit combination the attacker can guess or observe (SHAs are often public on GitHub).

### Likelihood Explanation
Requires: (1) the deployment uses the multi-org GitHub config schema (`Shipit.github_organizations` > 1), and (2) at least one configured org has no `webhook_secret` set — a state explicitly supported and documented by this engine's own config examples and test fixtures. Given that, the attacker's cost is a single unauthenticated HTTP POST with a crafted JSON body; no secrets, sessions, or GitHub App access are needed. This is fully repeatable and requires no timing or race conditions.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler#stacks`, cross-check that the organization actually used to verify the webhook signature matches the owner of `repository.full_name` (or `organization.login`) referenced by the handler, rejecting (422) on mismatch. Additionally, treat a blank/unset `webhook_secret` for any org in a multi-org config as a hard misconfiguration (fail closed) rather than silently accepting unsigned requests, since `GitHubApp#verify_webhook_signature`'s `return true unless webhook_secret` effectively disables signature verification for that org and permits payloads for any repository to be delivered under its identity.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual minitest addition)
test ":check_suite verified under org with no webhook_secret cannot act on another org's repository" do
  # Precondition: victim stack tracked under OrgOne/real-repo with commit sha "abc123" on branch "master"
  victim_commit = shipit_commits(:first) # sha "abc123", stack.repository.full_name == "OrgOne/real-repo"

  body = {
    action: "requested",
    check_suite: { head_sha: victim_commit.sha, head_branch: "master" },
    repository: {
      owner: { login: "OrgTwo" },       # attacker org, no webhook_secret configured
      full_name: "OrgOne/real-repo"     # victim org's real tracked repository
    }
  }.to_json

  @request.headers['X-Github-Event'] = 'check_suite'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid signature

  # Equality under test: verifying_org("OrgTwo") == repository_owner("OrgOne") ?  -> false
  assert_no_enqueued_jobs do
    post :create, body: body, as: :json
  end
  # Expect either 422 (if fixed) — current behavior: 200 OK and RefreshCheckRunsJob enqueued for victim_commit
end
```

Prior to a fix, this test would show `RefreshCheckRunsJob` enqueued for `victim_commit.id` despite the signature being verified only against `OrgTwo`'s (attacker's) empty secret, confirming the cross-organization write.

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

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/commit.rb (L152-154)
```ruby
    def schedule_refresh_check_runs!
      RefreshCheckRunsJob.perform_later(commit_id: id)
    end
```

**File:** app/models/shipit/commit.rb (L171-184)
```ruby
    def paginated_check_runs
      response = stack.handle_github_redirections do
        stack.github_api.check_runs(github_repo_name, sha, per_page: 100)
      end

      yield response.check_runs

      until stack.github_api.last_response.rels[:next].nil?
        page = stack.handle_github_redirections do
          stack.github_api.get(stack.github_api.last_response.rels[:next].href)
        end
        yield page.check_runs
      end
    end
```
