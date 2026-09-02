### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on unscoped or independently-controlled payload fields, letting one authenticated GitHub organization forge state for another organization's commits/stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) . Once the signature is accepted, event handlers act on *other* payload fields - `repository.full_name` for routing to a `Stack`/`Repository` [3](#0-2) , and, for `status` events, a completely unscoped `sha` lookup across the whole `Commit` table [4](#0-3) . The signature never binds the organization that authenticated the request to the repository/commit that is actually mutated, so an org whose webhook secret is known to the attacker (i.e., a legitimate tenant admin in a multi-org Shipit deployment) can forge a signed payload naming any other repository or any arbitrary commit SHA.

### Finding Description
`Shipit` supports multiple GitHub organizations, each with its own `webhook_secret` configured via `secrets.github` [5](#0-4) . `verify_webhook_signature` performs a straightforward HMAC comparison of the raw JSON body against that organization's secret [6](#0-5) . The organization used to pick the secret is taken from the payload itself:

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Nothing subsequently checks that this "signing organization" matches the organization/repository that the handler actually mutates:

- `PushHandler`/other handlers resolve the target `Stack` via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` - an independent JSON field from `repository.owner.login` [3](#0-2) .
- `StatusHandler#process` does not scope by repository at all - it looks up commits globally by SHA: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .

Because the HMAC only proves "this body was signed with organization X's secret," and the body's `repository.owner.login` (used for signature routing) and `repository.full_name`/`sha` (used for the actual state mutation) are both attacker-controlled JSON fields with no cross-field validation, an attacker who legitimately administers organization X's GitHub App/webhook (and therefore knows X's `webhook_secret`) can:
1. Set `repository.owner.login` = `X` so `verify_signature` validates against X's known secret.
2. Set `repository.full_name` / `sha` to values belonging to a completely different organization's repository or commit.

The signature check passes even though the mutated resource has nothing to do with organization X.

### Impact Explanation
This breaks the required binding: *"an organization that authenticated versus the repository that is written."* Concretely:
- A `status` webhook forged this way lets an authenticated-but-unrelated organization write a fabricated CI status (`state`, `context`, `target_url`, `description`) onto **any commit in the entire Shipit installation**, since the lookup is global (`Commit.where(sha: ...)`) with no repository/stack scoping [4](#0-3) . Shipit deploy gating (`ci.require`, documented in `README.md`) relies on commit statuses to decide whether a commit is safe to deploy; a forged "success" status on a victim's commit can defeat that gate, leading toward an unauthorized deploy of the victim's stack.
- A `push` webhook forged this way can trigger `GithubSyncJob`/`stack.sync_github` for any repository whose `full_name` the attacker names, as `Handler#stacks` resolves purely from `repository.full_name` via `Repository.from_github_repo_name` [3](#0-2) , independent of which organization's secret validated the signature.

This satisfies the "unauthorized deploy" / cross-repository-write impact bar without requiring any Shipit session, API token, or repository write access on GitHub itself - only knowledge of one (potentially unrelated) organization's own configured `webhook_secret`, which that organization's own administrators legitimately possess.

### Likelihood Explanation
Exploitability requires a multi-tenant Shipit deployment where multiple GitHub organizations are configured (`secrets.github` with per-org sections, as tested in `test/dummy/config/secrets_double_github_app.yml` referenced by `test/unit/shipit_test.rb`) [7](#0-6) , and where the attacker administers at least one such organization's GitHub App/webhook secret. This is a realistic scenario for SaaS-style or shared Shipit installations serving several organizations/teams, and requires no compromise of the victim organization's credentials, TLS interception, or GitHub write access - only crafting an HTTP POST with a valid HMAC computed from a secret the attacker already legitimately holds.

### Recommendation
After signature verification, re-derive the organization from the same field(s) used to route the event (`repository.full_name`'s owner segment, or the resolved `Stack`/`Repository`'s known owner) and assert it matches `repository_owner` used to select the webhook secret before dispatching to any handler. For `StatusHandler`, scope the `Commit` lookup by the repository resolved from the verified organization/full_name rather than a bare global `sha` lookup.

### Proof of Concept
1. Attacker administers GitHub App integration for `org-attacker` in a multi-org Shipit instance and knows `webhook_secret_attacker` (their own configured secret).
2. Attacker crafts a `status` event payload:
   ```json
   {
     "sha": "<victim commit sha, e.g. the SHA about to be deployed on org-victim/app>",
     "state": "success",
     "context": "required-ci-check",
     "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/some-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_attacker, body)` and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` = `org-attacker`, fetches `Shipit.github(organization: 'org-attacker')`, and the HMAC validates successfully [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a fabricated "success" status on the victim's commit, regardless of `org-victim`'s actual CI state [4](#0-3) , potentially satisfying `ci.require` and enabling an unauthorized deploy of `org-victim`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
