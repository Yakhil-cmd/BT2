Confirmed the exploit path is real and unaltered by any existing guard. `verify_signature` resolves the GitHub App purely from `repository.owner.login` [1](#0-0) [2](#0-1) , while `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that organization's config has no `webhook_secret` [3](#0-2) . `#create` then independently re-parses the same raw body and dispatches to handlers keyed on `repository.full_name`, a field entirely disconnected from the one used for verification [4](#0-3) [5](#0-4) . `PushHandler#process` resolves stacks from that unrelated `full_name` and calls `sync_github` with no re-check that it belongs to the verified organization [6](#0-5) .

### Title
Webhook org used for signature verification is disconnected from repository used for mutation, enabling cross-tenant `sync_github` when any configured org lacks `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` to validate against using `repository.owner.login`, but `#create`'s dispatch to handlers (e.g. `PushHandler`) uses `repository.full_name` from the same attacker-supplied JSON body, with no check that these refer to the same organization. If any org configured in `Shipit.github_apps` has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, letting an anonymous attacker forge a payload whose `owner.login` names that weak org while `full_name` names an arbitrary other org's private repo, causing that repo's stack to run `sync_github`.

### Finding Description
The broken binding: organization verified by signature (`repository.owner.login`, "orgA", no secret configured) == organization owning the mutated repository (derived from `repository.full_name`, "orgB"). This is false, and nothing in the code enforces it.

- `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and calls `Shipit.github(organization: repository_owner)` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is not configured for that org, before ever inspecting the signature header or the body [3](#0-2) . `webhook_secret` is populated from `@config[:webhook_secret].presence`, so it is legitimately `nil` if the operator leaves it blank [7](#0-6) ; the project's own sample/dummy configs show this field left empty for one or more orgs [8](#0-7) .
- `#create` re-parses `request.raw_post` and dispatches to `Shipit::Webhooks.for_event(event)` handlers with the full parsed body [4](#0-3) .
- The base `Handler` resolves `stacks` via `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` — a completely independent key from the one used for verification [5](#0-4) .
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack for that repository/branch [6](#0-5) .

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` (absent or garbage), and a JSON body containing `{"repository": {"owner": {"login": "orgA"}, "full_name": "orgB/private-repo"}, "ref": "refs/heads/master", "after": "<sha>"}`, where `orgA` is configured in `Shipit.github_apps` with no `webhook_secret` and `orgB` is a different, legitimately secured org whose `orgB/private-repo` has a tracked `Stack`.

Exploit flow: `verify_signature` looks up `Shipit.github(organization: 'orgA')`, calls `verify_webhook_signature` which returns `true` immediately because `orgA` has no secret — the signature header is never checked. `#create` then dispatches the same body to `PushHandler`, which resolves `orgB/private-repo`'s stack via `full_name` and invokes `sync_github`, entirely bypassing any need for `orgB`'s credentials.

Existing guards do not stop this: `drop_unhandled_event` only filters unregistered event types [9](#0-8) ; `GithubOrganizationUnknown` only triggers if `orgA` is absent from config entirely, not if it exists without a secret [10](#0-9) ; and `ExplicitParameters` schemas for `PushHandler` only require `ref`/`after` types, performing no cross-check against the verified organization [11](#0-10) .

### Impact Explanation
An unauthenticated internet request triggers `Stack#sync_github` for an arbitrary tracked repository/stack belonging to a different, properly-secured organization, as long as any single org in the multi-tenant `Shipit.github_apps` config has no `webhook_secret`. This matches "a payload for one repository mutating another's stack" under the Critical category. The blast radius spans every org and stack configured on the Shipit instance — one weak/misconfigured org's webhook secret compromises signature-based tenant isolation for all other orgs, and the attack is fully repeatable against any known `full_name`/branch combination with no rate limiting concerns in scope.

### Likelihood Explanation
Requires only: (1) a multi-org Shipit deployment (`Shipit.github_apps`) where at least one configured org has no `webhook_secret` — a state the engine's own sample configs (`test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`) demonstrate is a valid, non-error configuration; (2) knowledge of that weak org's login name (discoverable/guessable, e.g. from public GitHub org names) and the target org/repo's `full_name`. No secrets, sessions, or GitHub App credentials are needed. Attacker cost is a single crafted HTTP POST.

### Recommendation
Bind signature verification to the same repository actually used for mutation: derive the org used for both `Shipit.github(organization: ...)` lookup and the dispatched handler's `repository_name` from one single, consistently-read value, and reject the request if `repository.full_name`'s owner segment does not match `repository.owner.login` (or simply always derive the organization from `full_name`'s owner segment). Additionally, require `webhook_secret` to be present for every configured org (fail loudly at boot/config-load time if any org lacks one) rather than silently allowing signature-free acceptance.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb`, stub `Shipit.secrets.github` (or use a fixture like `secrets_double_github_app.yml`) with `OrgWeak` having `webhook_secret: nil` and `OrgStrong` having a real `webhook_secret`. Create a tracked `Stack`/`Repository` for `OrgStrong/private-repo` on branch `master`. Then:

```ruby
test "cross-org forged push bypasses signature via org lacking webhook_secret" do
  request.headers['X-Github-Event'] = 'push'
  request.headers['X-Hub-Signature'] = 'sha1=garbage'

  body = {
    'ref' => 'refs/heads/master',
    'after' => 'deadbeef',
    'repository' => {
      'owner' => { 'login' => 'OrgWeak' },      # no webhook_secret configured
      'full_name' => 'OrgStrong/private-repo'   # belongs to a different, secured org
    }
  }.to_json

  Stack.any_instance.expects(:sync_github).with(expected_head_sha: 'deadbeef')

  post :create, body:, as: :json
  assert_response :ok
end
```

Assert both sides of the binding explicitly before/after: `repository_owner == 'OrgWeak'` (used in `Shipit.github(organization:)`) while the mutated stack's repository `full_name == 'OrgStrong/private-repo'` — demonstrating the org that "verified" the request never matches the org whose stack is mutated, and no code path enforces equality.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-10)
```ruby
        params do
          requires :ref
          requires :after
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
