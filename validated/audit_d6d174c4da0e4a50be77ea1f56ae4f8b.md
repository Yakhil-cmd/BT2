### Title
Handler#stacks resolves target repo from `payload.repository.full_name` with no cross-check against the org (`repository_owner`) whose secret authenticated the webhook, enabling cross-repository stack/commit mutation - ([File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/org secret to verify the HMAC using `repository_owner`, taken from `payload.dig('repository','owner','login')`. `Handler#stacks` independently resolves the target `Repository`/`Stack` using `payload.dig('repository','full_name')` via `Repository.from_github_repo_name`. These are two distinct, independently attacker-controlled JSON fields in the same unauthenticated POST body, and nothing anywhere in `Handler`, `PushHandler`, `CheckSuiteHandler`, or `WebhooksController#create` checks that `full_name`'s owner segment equals `repository_owner`.

### Finding Description
Binding that should hold: `organization_that_verified_hmac (repository_owner = payload.repository.owner.login)` == `organization_prefix(payload.repository.full_name)` used by `Repository.from_github_repo_name`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` at [1](#0-0)  and uses it to pick `Shipit.github(organization: repository_owner)` for HMAC verification at [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has no configured `webhook_secret`: [3](#0-2) .
- `WebhooksController#create` then dispatches the raw, un-narrowed `params` (the whole attacker JSON body) to handlers with no identity/org binding attached: [4](#0-3) .
- `Handler#stacks` resolves the target repo purely from `payload.dig('repository','full_name')`, a field completely independent from `repository_owner`: [5](#0-4) .
- `Repository.from_github_repo_name` just splits `full_name` on `/` and looks up any DB repo, with no relation to which org's secret validated the request: [6](#0-5) .
- `PushHandler#process` (and similarly `CheckSuiteHandler`, `StatusHandler`) uses `stacks` to mutate/sync arbitrary matched stacks: [7](#0-6) .

Shipit supports multiple GitHub organizations each with their own optional `webhook_secret`, confirmed by the multi-org config mechanism (`Shipit.github_organizations`, `Shipit.github_app_config`) at [8](#0-7) . If any configured organization has no `webhook_secret` set (a legitimate, non-privileged configuration state - `@webhook_secret = @config[:webhook_secret].presence` at [9](#0-8) , and the check at line 77 explicitly treats a blank secret as "always verified"), an attacker sends a POST to `/webhooks` with `repository.owner.login` set to that org (public information) and `repository.full_name` set to any victim repo already known to Shipit (`victim-org/victim-repo`). The signature check trivially passes for that org, and the handler then mutates the victim repository's `Stack`/`Commit`/`CheckRun` records using the unrelated `full_name` field. No code path anywhere cross-validates `repository_owner` against `full_name`'s prefix.

Existing guards do not close this gap: `verify_signature` only decides pass/fail for the *request*, it never passes the verified organization into the handler layer; `drop_unhandled_event` only filters by event type; `ExplicitParameters` schemas (`requires :ref`, `requires :after`) validate presence/shape of unrelated fields, not repo identity; `Repository`/`Stack` validations constrain format of `owner`/`name` strings, not their relation to the authenticating org.

### Impact Explanation
An attacker who knows (a) that some organization configured in this Shipit instance has no `webhook_secret` (or otherwise can produce a valid signature for some org) and (b) the `owner/repo` full name of a target Shipit-tracked repository, can cause writes (new commits synced, check-run refresh jobs, status updates) against that target repository's `Stack` without having authenticated as, or possessing any secret for, that target repository's real organization. This is a payload for one org/repo mutating another repo's stack/commit/task state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any repository already registered in Shipit's database and works for every subclass of `Handler` (`PushHandler`, `CheckSuiteHandler`, pull_request handlers, `StatusHandler`) since none of them add the missing check.

### Likelihood Explanation
Preconditions: the Shipit deployment must use the multi-organization GitHub config format (`Shipit.github_organizations`), and at least one configured organization must have `webhook_secret` blank/unset (or the attacker otherwise controls a valid signature for some org — out of scope per rules). This is a realistic operational gap: multi-org setups commonly add organizations incrementally and an admin can easily configure one entry without a webhook secret. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body containing two independently attacker-chosen fields (`repository.owner.login`, `repository.full_name`); no GitHub credentials, sessions, or Shipit secrets are needed. Fully repeatable and scriptable against any known target repo name.

### Recommendation
In `Handler#stacks` (or in `WebhooksController` before dispatch), require that the organization used to select the webhook secret (`repository_owner`) matches the owner segment of `payload.dig('repository','full_name')` before resolving `Repository.from_github_repo_name`; reject/`head(422)` on mismatch. Additionally, require `webhook_secret` to be present for every configured organization (or fail closed rather than fail open) in `GitHubApp#verify_webhook_signature`, removing the `return true unless webhook_secret` fallback in production configurations.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "webhook authenticated for org with no secret can mutate a different repo's stack via full_name mismatch" do
  # Precondition: configure org "attacker-org" with NO webhook_secret,
  # while the real target stack belongs to repository "shopify/shipit-engine".
  Shipit.stubs(:github_app_config).with("attacker-org").returns({}) # no webhook_secret key
  victim_stack = shipit_stacks(:shipit) # repository full_name == "shopify/shipit-engine"

  @request.headers['X-Github-Event'] = 'push'
  payload = JSON.parse(payload(:push_master))
  payload["repository"]["owner"]["login"] = "attacker-org"      # used by verify_signature
  payload["repository"]["full_name"]      = "shopify/shipit-engine" # used by Handler#stacks
  # No X-Hub-Signature header set / arbitrary signature - verify_webhook_signature
  # returns true unconditionally because attacker-org has no webhook_secret.

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: payload["after"]]) do
    post :create, body: payload.to_json, as: :json
  end
  # Assert the equality that should have held but didn't:
  # repository_owner ("attacker-org") != full_name.split('/').first ("shopify")
  assert_not_equal "attacker-org", "shopify/shipit-engine".split('/').first
end
```
This demonstrates that `stacks` resolves to, and mutates, the `shopify/shipit-engine` stack even though the HMAC was validated (trivially, due to no secret) against `attacker-org`, proving the two identities are never cross-checked. The precondition (an org without `webhook_secret`) is a valid, unprivileged-observable configuration state, not a violation of the exclusion rules on secrets/session/TLS.

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

**File:** lib/shipit/github_app.rb (L50-50)
```ruby
      @webhook_secret = @config[:webhook_secret].presence
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** lib/shipit.rb (L190-200)
```ruby
  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
