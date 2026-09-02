### Title
Webhook signature is verified against `repository.owner.login`, but Stack selection uses the unrelated `repository.full_name` field, allowing cross-tenant `sync_github` forgery - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb, app/models/shipit/webhooks/handlers/push_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` to validate the HMAC using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` in the attacker-supplied JSON body itself. `Handler#stacks` and `PushHandler#process` independently resolve the target `Stack` from a different field of the same attacker-supplied body, `payload.dig('repository', 'full_name')`. Nothing in the request path asserts that these two fields are consistent, so an attacker who legitimately owns a Shipit-registered organization (and therefore knows that organization's `webhook_secret`) can sign a payload where `owner.login` is their own org but `full_name` points at a victim org/repo, causing `stack.sync_github` to run against the victim's `Stack`.

### Finding Description
The broken binding, stated explicitly:

`repository.owner.login` (the value used to authenticate the HMAC signature in `verify_signature`) is assumed to equal `repository.full_name.split('/').first` (the value used by `PushHandler`/`Handler#stacks` to select which `Stack` receives `sync_github`). This assumption only holds for genuine GitHub-originated deliveries, because GitHub itself guarantees internal consistency of its own payload. It is never checked by Shipit's own code.

Code path:
- `WebhooksController#verify_signature` computes `repository_owner` from the raw JSON body: [1](#0-0) , then picks the `GitHubApp` config/secret for that org and verifies the signature against it: [2](#0-1) .
- Once verified, `WebhooksController#create` parses the raw body again and dispatches it, unmodified, to the matching handler: [3](#0-2) .
- `Handler#stacks`/`#repository_name` resolves the target repository purely from `payload.dig('repository', 'full_name')`, a completely different key of the same body, with no reference back to `repository_owner`: [4](#0-3) .
- `PushHandler#process` then calls `sync_github` on every non-archived stack of that resolved repository matching the branch: [5](#0-4) .
- `Shipit.github(organization:)` supports true multi-tenant configuration, where each org key in `secrets.github` has its own independent `webhook_secret`: [6](#0-5) , and `verify_webhook_signature` simply HMACs the raw body with whichever org's secret was selected: [7](#0-6) .

Exploit flow: an attacker who owns/administers `attacker-org` in a multi-tenant Shipit instance necessarily knows `attacker-org`'s `webhook_secret` (they had to enter it into GitHub's webhook settings for their own org). They send `POST /webhooks` directly (no GitHub involvement needed) with a JSON body where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`, `ref = "refs/heads/<victim-branch>"`, and `after = "<any sha>"`, signed with `attacker-org`'s secret in `X-Hub-Signature`. `verify_signature` looks up `attacker-org`'s config via `repository_owner`, computes the HMAC correctly, and passes. `PushHandler` then resolves the `Stack` for `victim-org/victim-repo` (a completely different, unrelated tenant) and calls `sync_github` on it.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type header, not payload consistency; `verify_signature` never re-derives `repository_owner` from `full_name` or cross-checks the two; `ExplicitParameters` schema in `PushHandler` only validates presence of `ref`/`after`, not repository identity; there is no model validation tying `Repository`/`Stack` lookup to the authenticated org.

### Impact Explanation
The attacker can trigger `Stack#sync_github` on any Stack belonging to a repository they do not own or administer, as long as they can name its `owner/repo` full name (public information for public repos) and control any single tenant org's webhook secret in the same Shipit instance. This is a cross-tenant, payload-for-one-repository-mutates-another's-stack scenario, matching the Critical impact category. It is fully repeatable — a single crafted POST per invocation, at will, against any stack/branch in the instance, without any GitHub interaction, session, or API token.

### Likelihood Explanation
This is only exploitable in a multi-tenant Shipit deployment (`secrets.github` keyed by multiple organizations, each with its own `webhook_secret`), and only by an attacker who legitimately administers at least one such tenant org (so they know that org's own `webhook_secret`, which they were given specifically to configure their own GitHub webhook). Given that Shipit explicitly supports and documents this multi-org configuration (`github_app_config`, `github_organizations` in `lib/shipit.rb`), this is a realistic deployment shape, and the attack itself requires only a single crafted HTTP POST with correctly computed HMAC-SHA1 — no other secrets, sessions, or privileged roles are needed.

### Recommendation
In `WebhooksController#verify_signature` (or immediately after, before dispatch), assert that `params.dig('repository', 'owner', 'login')` matches the owner segment of `params.dig('repository', 'full_name')` before allowing any handler to process the payload, and reject (422) on mismatch. Alternatively, derive the org used for stack lookup directly from the same authenticated `repository_owner` value rather than re-deriving it from `full_name` independently in `Handler#repository_name`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, no live GitHub call needed since `Shipit.github` reads from configured `secrets.github` and HMAC is purely local):

```ruby
test "push webhook with owner.login for attacker-org but full_name for victim-org syncs victim's stack" do
  # Setup: configure secrets.github with two tenants: 'attacker-org' and 'victim-org',
  # each with distinct webhook_secret (mirrors test/dummy/config/secrets_double_github_app.yml).
  victim_stack = shipit_stacks(:shipit) # belongs to victim-org/victim-repo, on branch 'master'

  payload = {
    'ref' => 'refs/heads/master',
    'after' => 'deadbeef' * 5,
    'repository' => {
      'owner' => { 'login' => 'attacker-org' },   # signed identity
      'full_name' => 'victim-org/victim-repo'       # stack-selection identity
    }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', attacker_org_webhook_secret, payload)

  assert_equal 'attacker-org', JSON.parse(payload).dig('repository', 'owner', 'login')
  assert_equal 'victim-org',   JSON.parse(payload).dig('repository', 'full_name').split('/').first
  # Binding under test: these two must be equal for the design to be safe -- they are NOT.
  refute_equal JSON.parse(payload).dig('repository', 'owner', 'login'),
               JSON.parse(payload).dig('repository', 'full_name').split('/').first

  victim_stack.expects(:sync_github).with(expected_head_sha: 'deadbeef' * 5)

  post '/webhooks', params: payload, headers: {
    'X-Github-Event' => 'push',
    'X-Hub-Signature' => signature,
    'Content-Type' => 'application/json'
  }

  assert_response :ok # signature accepted using attacker-org's secret
  # mocha expectation on victim_stack.sync_github verifies the foreign stack was mutated
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
