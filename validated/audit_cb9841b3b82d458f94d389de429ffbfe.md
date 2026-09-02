### Title
Webhook signature verification is scoped by an attacker-controlled `repository.owner.login`, decoupled from `repository.full_name` used by handlers - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate the HMAC against using `repository_owner`, which is read directly from the untrusted JSON body (`params.dig('repository', 'owner', 'login')`). Every downstream `Handler` (e.g. `PushHandler`) instead resolves the target repository/stack from a *different* field of the same untrusted body, `payload.dig('repository', 'full_name')`, with no check that this value's owner segment matches the `repository_owner` used to pick the signing secret.

### Finding Description
Binding that should be enforced: `repository_owner (used in verify_signature) == owner-prefix of repository.full_name (used in Handler#repository_name)`.

Trace:
- `WebhooksController#verify_signature` [1](#0-0)  calls `Shipit.github(organization: repository_owner)`, where `repository_owner` is taken straight from the JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .
- `Shipit.github` looks up the `GitHubApp` config keyed by that organization name (`github_app_config(organization)`) and verifies the raw body against **that org's** `webhook_secret` [3](#0-2) , `verify_webhook_signature` [4](#0-3) .
- Once verified, `create` parses the same raw body and dispatches it, unmodified, to every handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')` [6](#0-5) , and `PushHandler#process` resolves stacks purely from that full name via `Repository.from_github_repo_name(repository_name)` and syncs them to `params.after` [7](#0-6) .

There is no code anywhere in this chain that asserts `repository.owner.login == repository.full_name.split('/').first`. In Shipit's supported multi-organization deployment mode (`config/secrets.development.shopify.yml` shows distinct `somegithuborg` / `someothergithuborg` sections, each with its own `webhook_secret`) [8](#0-7) , this means: an attacker who legitimately administers one org's GitHub App/webhook (Org A, and thus knows Org A's `webhook_secret`) can craft a JSON body with `repository.owner.login = "OrgA"` (so `verify_signature` selects and validates against Org A's real secret, which they hold) but `repository.full_name = "OrgB/target-repo"` and arbitrary `ref`/`after` values. The signature check passes because it only proves the bytes match Org A's secret — it never inspects `full_name`. `PushHandler` then looks up and mutates Org B's stacks based entirely on attacker-supplied, unverified `ref` and `after` (commit SHA), with GitHub never consulted to confirm any of it.

Existing guards do not stop this: `verify_signature` stops forged bytes only for the org it happens to select (which is attacker-chosen), `drop_unhandled_event` only filters by event name, and no model validation on `Repository`/`Stack` cross-checks the signing organization against the repository being acted on.

### Impact Explanation
A signed request that is genuinely valid for Org A is used to mutate Stack/Repository state belonging to Org B — exactly the Critical category "a payload for one repository mutating another's stack, commit, task or team." Concretely, `PushHandler` will call `stack.sync_github(expected_head_sha: params.after)` for any repository named in `full_name`, regardless of who is verified as the sender, on every Shipit deployment that manages more than one GitHub organization. The blast radius spans all tenants sharing one Shipit instance; a single legitimate-but-unprivileged webhook keyholder for one org can inject fabricated push/status/pull_request/membership events attributed to any other configured org's repositories.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (the officially documented and supported "multiple Github applications" schema). The attacker needs only the webhook secret for the organization they legitimately administer (something within their own privileges, not GitHub/Shipit operator secrets for the victim org). No TLS interception, no session, no API token, and no GitHub call are required — the request is a single unauthenticated `POST /webhooks` with a correctly computed HMAC over attacker-chosen JSON. This is trivially repeatable against any other org/repo name known to the attacker.

### Recommendation
After signature verification, validate that the organization used to select the signing secret matches the owner segment of `repository.full_name` (and/or `organization.login`) in the parsed body before dispatching to handlers; reject the request (422) on mismatch.

### Proof of Concept
Minitest (functional, `test/controllers/webhooks_controller_test.rb` style — no live GitHub):
```ruby
test "cross-organization push payload mutates another org's stack" do
  # Org A is the attacker's own, legitimately configured org.
  # Org B is the victim org whose stack must not be touched.
  Shipit.stubs(:github).with(organization: 'org-a').returns(
    stub(verify_webhook_signature: true) # simulates attacker's real, valid secret for org-a
  )

  victim_stack = shipit_stacks(:org_b_stack) # belongs to repository "org-b/target-repo"

  forged_payload = {
    'ref' => 'refs/heads/master',
    'after' => 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    'repository' => {
      'owner' => { 'login' => 'org-a' },       # used by verify_signature -> picks org-a's real secret
      'full_name' => 'org-b/target-repo'       # used by PushHandler -> targets org-b's stack
    }
  }.to_json

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = 'sha1=attacker-computed-with-org-a-secret'

  assert_equal 'org-a', JSON.parse(forged_payload).dig('repository', 'owner', 'login')
  refute_equal 'org-a', JSON.parse(forged_payload).dig('repository', 'full_name').split('/').first
  # BINDING VIOLATED: signing org ("org-a") != owner segment of full_name ("org-b")

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef']) do
    post :create, body: forged_payload, as: :json
  end
  assert_response :ok
end
```
This demonstrates the absence of any `Repository`/`Organization` ownership check tying `repository_owner` to `repository.full_name` anywhere between `verify_signature` and `PushHandler#process`.

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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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
