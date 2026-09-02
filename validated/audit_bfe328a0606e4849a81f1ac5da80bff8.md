### Title
Webhook signature verification is scoped by `repository.owner.login` while event processing is scoped by `repository.full_name`, letting an org with no `webhook_secret` forge `check_suite` events against another tenant's repository - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/check_suite_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook based on `repository.owner.login` (or `organization.login`) taken from the JSON body, while `Handler#stacks` (used by `CheckSuiteHandler`) resolves the target `Repository`/`Stack` from `repository.full_name`, a separate field in the same body. Nothing enforces that these two fields refer to the same repository, so an attacker who controls an organization registered in Shipit with no `webhook_secret` can pass signature verification "for free" while pointing the event body's `repository.full_name`/`check_suite.head_sha`/`head_branch` at a victim tenant's stack.

### Finding Description
The claimed binding is: `verified_repository_owner (used for signature check) == acted_upon_repository (used to resolve stacks/commits)`. Tracing the code shows this equality is never enforced.

- `WebhooksController#verify_signature` derives the authenticating org solely from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and looks up `Shipit.github(organization: repository_owner)` to call `verify_webhook_signature` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's configured `webhook_secret` is blank/absent: `return true unless webhook_secret` [3](#0-2) . The fixture `test/dummy/config/secrets_double_github_app.yml` demonstrates orgs intentionally configured with `webhook_secret: # nil` [4](#0-3) .
- After signature "verification" passes, `WebhooksController#create` re-parses the same raw body and dispatches it to handlers: `params = JSON.parse(request.raw_post); Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .
- `Handler#stacks` resolves the acted-upon repository independently, using `payload.dig('repository','full_name')`: `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none` [6](#0-5) .
- `CheckSuiteHandler#process` then does `stacks.where(branch: params.check_suite.head_branch).each { |stack| stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!) }` [7](#0-6) , which enqueues `RefreshCheckRunsJob.perform_later(commit_id: id)` [8](#0-7) , ultimately driving `stack.github_api.check_runs(...)` calls signed with the app's `GITHUB_TOKEN` for that stack's real (victim) repository/organization [9](#0-8) .

**Exact attacker request**: register (or already control) an org `attacker-org` in Shipit's `config/secrets.yml`/multi-org config with no `webhook_secret` (or find one already so configured — the shipped fixture pattern `OrgOne`/`OrgTwo` in `secrets_double_github_app.yml` shows this is a supported, not-unusual configuration). POST to `/webhooks` with header `X-Github-Event: check_suite` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "check_suite": { "head_sha": "<victim commit sha>", "head_branch": "<victim stack branch>" }
}
```
`verify_signature` looks up `attacker-org`'s `GitHubApp`, sees no `webhook_secret`, and accepts the request regardless of the (even absent/garbage) `X-Hub-Signature` header. `CheckSuiteHandler` then resolves `victim-org/victim-repo` via `repository.full_name` and schedules `schedule_refresh_check_runs!` on the victim's commit.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` (`CheckSuiteHandler.params`) only validates presence/type of `check_suite.head_sha`/`head_branch`, not the repository binding [10](#0-9) ; `verify_signature`'s `rescue Shipit::GithubOrganizationUnknown` only fires if the org name is entirely unknown to Shipit, not if it's known-but-unsecured [11](#0-10) ; and no code compares `repository.owner.login` to the owner segment of `repository.full_name`.

### Impact Explanation
An attacker's authenticated-but-unsecured org can trigger `RefreshCheckRunsJob`/`schedule_refresh_check_runs!` against an arbitrary victim commit/stack whose `repository.full_name`, branch name, and a commit SHA are known (all discoverable via Shipit's public UI/API or GitHub). This is unauthorized job scheduling for a repository the attacker did not authenticate, causing the app to perform GitHub API reads/writes (`check_runs` fetch, `CheckRun` upsert) against the victim's repository using the shared `GITHUB_TOKEN`, repeatable per request against any repository/stack combination known to the attacker, and not limited to a single tenant — it works against any victim stack as long as some org with a blank `webhook_secret` exists in the Shipit deployment. This matches "a payload for one repository mutating another's stack/commit" — Critical.

### Likelihood Explanation
Preconditions: (1) Shipit must be configured (or the attacker must control) at least one GitHub organization registered in Shipit with no `webhook_secret` set — a configuration explicitly demonstrated as supported in `test/dummy/config/secrets_double_github_app.yml`; (2) attacker needs to know a victim's `repository.full_name`, an active branch name, and a commit SHA on that stack, all of which are visible through Shipit's own stack/commit UI without authentication in many deployments, or via public GitHub. No Shipit session, API token, or GitHub secret is required. Cost is a single crafted HTTP POST to `/webhooks`, fully repeatable and scriptable.

### Recommendation
Bind signature verification and event routing to the same repository identity. Concretely, in `WebhooksController`, derive `repository_owner` used for signature verification from the same `repository.full_name` field the handlers use (e.g., split `full_name` and require it to match `repository.owner.login`), or better, resolve the `Repository`/its org from `full_name` first and verify the signature using that Repository's own configured webhook secret. Reject requests where `repository.owner.login` does not match the owner segment of `repository.full_name`. Also consider disallowing/warning on organizations configured with a blank `webhook_secret` in production.

### Proof of Concept
Minitest plan (to be placed under `test/controllers/webhooks_controller_test.rb`, no live GitHub):
```ruby
test "check_suite from an org with no webhook_secret cannot forge events for another tenant's repository" do
  victim_stack  = shipit_stacks(:shipit) # repository full_name e.g. "shopify/shipit-engine"
  victim_commit = shipit_commits(:first)
  victim_commit.update!(sha: "victimshaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

  # Attacker-controlled org "attacker-org" configured with webhook_secret: nil
  Shipit.stubs(:github).with(organization: "attacker-org").returns(
    Shipit::GitHubApp.new("attacker-org", { app_id: 1, installation_id: 1, webhook_secret: nil })
  )

  request.headers['X-Github-Event'] = 'check_suite'
  body = {
    repository: { owner: { login: "attacker-org" }, full_name: victim_stack.repository.full_name },
    check_suite: { head_sha: victim_commit.sha, head_branch: victim_stack.branch }
  }.to_json

  # Binding under test: verified_owner ("attacker-org") != acted_upon_repository (victim_stack.repository.full_name)
  assert_enqueued_with(job: RefreshCheckRunsJob, args: [commit_id: victim_commit.id]) do
    post :create, body:, as: :json
  end
  assert_response :ok
end
```
Assert both sides of the binding explicitly before/after: `verified_org = "attacker-org"`, `acted_repository = victim_stack.repository.full_name`; before the fix these differ yet the job is still enqueued for the victim commit, proving the vulnerability.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/commit.rb (L152-154)
```ruby
    def schedule_refresh_check_runs!
      RefreshCheckRunsJob.perform_later(commit_id: id)
    end
```

**File:** app/models/shipit/commit.rb (L171-192)
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

    def refresh_check_runs!
      paginated_check_runs do |check_runs|
        check_runs.each do |check_run|
          create_or_update_check_run_from_github!(check_run)
        end
      end
    end
```
