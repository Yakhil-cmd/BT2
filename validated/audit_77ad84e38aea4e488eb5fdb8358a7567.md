### Title
Signature verification is keyed by `repository.owner.login` while stack mutation is keyed by `repository.full_name`, letting a payload for a secret-less org write to any other repository's `Stack` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `repository_owner` (`params.dig('repository','owner','login')`), but `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository` (used by `PushHandler` and all other handlers) resolve the target `Repository`/`Stack` using `payload.dig('repository','full_name')` — a value that is never checked against the verified organization. If any configured GitHub App organization has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` returns `true` unconditionally for that organization, allowing an unauthenticated request to name an arbitrary `full_name` belonging to a different, secret-protected organization and have it processed by the handler.

### Finding Description
The binding claimed to hold is: `organization used in verify_signature (repository.owner.login)` == `organization implied by repository.full_name (used to resolve the mutated Stack)`. Tracing the code shows this equality is **never enforced** anywhere in the request lifecycle.

- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) , where `repository_owner` is read solely from `params.dig('repository','owner','login')` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved org's `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) . This is a very common configuration state — every example/secrets template in the repo ships with `webhook_secret: # nil` [4](#0-3)  and the test dummy app's own secrets have `"webhook_secret": null` [5](#0-4) .
- After `verify_signature` passes, `#create` re-parses the same raw body and dispatches to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [6](#0-5) .
- `PushHandler#process` finds stacks via the base `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` [7](#0-6) , then mutates matching stacks: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` [8](#0-7) .

Nowhere is `params.dig('repository','full_name')`'s owner segment compared to `repository_owner`/the verified org. `Shipit.github(organization:)` in multi-org mode only checks that the named org exists in config (raising `GithubOrganizationUnknown` → 422 if not) [9](#0-8) ; it performs no relationship check to `full_name`.

**Exploit flow (single request):** In a multi-org deployment where org `attacker-org` is configured (so `Shipit.github(organization: 'attacker-org')` succeeds, avoiding the 422 from `GithubOrganizationUnknown`) but has `webhook_secret` blank/unset, an attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim/repo"}, "ref": "refs/heads/main", "after": "<sha>"}
```
`verify_signature` resolves the `GitHubApp` for `attacker-org`, whose blank secret makes `verify_webhook_signature` return `true` regardless of the (even absent) `X-Hub-Signature` header — no 422. `#create` then calls `PushHandler.call(params)`, which looks up `victim/repo` (an org the attacker does not control and never authenticated for) and calls `sync_github` on its `Stack`, an unauthorized cross-tenant write.

Existing guards do not stop this: `drop_unhandled_event` only checks the event name has a handler; `ExplicitParameters` schema for `PushHandler` only requires `ref`/`after` and does not validate `repository.full_name` against `repository.owner.login`; `verify_signature`'s only cross-check is organization *existence* in config, not ownership of `full_name`.

### Impact Explanation
A payload that authenticates for one (secret-less) GitHub organization can trigger writes (via `PushHandler#process` → `Stack#sync_github`, and analogously via other handlers keyed on `repository.full_name` such as `StatusHandler`, `CheckSuiteHandler`, and the `PullRequest::*` handlers) against a `Stack`/`Commit` belonging to an entirely different repository/organization that the attacker never authenticated as. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius spans every repository configured in the same Shipit instance, and is repeatable per request without rate limiting concerns (out of scope here, but repeatability itself is unrestricted).

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`secrets.github` keyed by org, per `github_app_config`) where at least one configured organization has no `webhook_secret` set — a state explicitly present as the default/example in this repo's own templates and test fixtures. Given that, the attacker needs no credentials, sessions, or GitHub secrets: a single unauthenticated HTTP POST suffices, and the "attacker-org" identity used need not have any real relationship to the victim repository named in `full_name`. Attacker cost is a single, trivially reproducible HTTP request.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#initialize`/`#repository_name`), verify that the organization segment of `payload.dig('repository','full_name')` (i.e., its owner) matches the `repository_owner` (or `organization.login`) whose `GitHubApp`/secret was used to authenticate the request, rejecting the request (422) on mismatch. Additionally, do not allow `verify_webhook_signature` to silently pass for organizations acting on payloads referencing a different organization's repository, and consider requiring a non-blank `webhook_secret` for any organization capable of matching cross-org `full_name` payloads.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative, ActionDispatch::IntegrationTest)
test "cross-org push forgery bypasses signature check and mutates victim stack" do
  # Setup: multi-org secrets with 'attacker-org' configured but webhook_secret blank,
  # and a pre-existing victim Stack for repository 'victim/repo' (branch 'main').
  victim_stack = shipit_stacks(:victim) # repository full_name == 'victim/repo', branch 'main'

  payload = {
    repository: { owner: { login: 'attacker-org' }, full_name: 'victim/repo' },
    ref: 'refs/heads/main',
    after: 'deadbeefcafebabefeedface0000000000000000'
  }.to_json

  assert_equal 'attacker-org', JSON.parse(payload).dig('repository', 'owner', 'login')
  assert_equal 'victim/repo', JSON.parse(payload).dig('repository', 'full_name')
  refute_equal JSON.parse(payload).dig('repository', 'owner', 'login'),
               JSON.parse(payload).dig('repository', 'full_name').split('/').first
  # Binding under test: verifying org ('attacker-org') != mutated stack's org ('victim')

  victim_stack.expects(:sync_github).with(expected_head_sha: 'deadbeefcafebabefeedface0000000000000000')

  post '/webhooks', params: payload, headers: { 'X-Github-Event' => 'push', 'Content-Type' => 'application/json' }
  # No X-Hub-Signature header sent at all

  assert_response :ok # NOT 422 — signature check bypassed via attacker-org's blank secret
end
```

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

**File:** test/dummy/config/secrets_double_github_app.yml (L6-7)
```yaml
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** test/dummy/config/secrets.test.json (L12-12)
```json
    "webhook_secret": null,
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
