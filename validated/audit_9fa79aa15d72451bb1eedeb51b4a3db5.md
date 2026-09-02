### Title
Cross-tenant webhook signature confusion lets an attacker's own org key authenticate a `membership` event that mutates another organization's `Shipit.github_teams` team - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify a webhook with by reading `organization.login` (or `repository.owner.login`) directly from the *unsigned* JSON body, then uses that same body's `team.id` to locate/mutate a `Team` record via `MembershipHandler`. Because the org used to pick the verifying secret and the org whose team is mutated are read independently from attacker-controlled JSON with no cross-check, an attacker who owns `attacker-org` (configured as a tenant in `Shipit.github` keyed by org) can sign a payload with their own `webhook_secret` while pointing `team.id` at a team belonging to a different tenant (e.g. `shopify`), causing `MembershipHandler#process` to add the attacker as a member of that team.

### Finding Description
The broken binding: `org_that_signed_the_body == org_whose_team_is_mutated`. Before tracing, on GitHub's real webhooks these are always equal (a team's org always signs its own team events). After tracing the code, they are not enforced to be equal.

- `WebhooksController#verify_signature` computes `repository_owner` purely from the body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and uses it to select the `GitHubApp` instance/secret: `Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)` [2](#0-1) . `Shipit.github` is explicitly multi-tenant, keyed by org, via `github_app_config(organization)` [3](#0-2) , and `verify_webhook_signature` only checks the HMAC against that org's own `webhook_secret` [4](#0-3) .
- The `create` action then dispatches the parsed body to handlers without any further binding to the verified organization: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .
- `MembershipHandler#process` looks up the team purely by `params.team.id` via `Team.find_or_create_by!(github_id: params.team.id)`; if the team already exists (e.g. `shopify`'s team), the block that would set `team.organization` is skipped entirely and the existing record is returned unchanged, then `team.add_member(member)` runs unconditionally [6](#0-5) . There is no check anywhere in the handler that `params.organization.login` (used only for signature routing) matches `team.organization` on the existing record.

Exploit flow: Shipit is configured with `Shipit.github` for both `attacker-org` (attacker's own webhook_secret) and `shopify` (a legitimate tenant with a `Team` already present in `Shipit.github_teams`, e.g. `shopify_developers`, whose `github_id` is public/discoverable via GitHub's team API or observed webhook traffic). The attacker crafts a `membership` webhook body: `{"action":"added","team":{"id":<shopify_developers.github_id>,...},"organization":{"login":"attacker-org"},"member":{"login":"attacker-login"}}`, signs it with `attacker-org`'s own `webhook_secret` (which they legitimately possess as owner of that org/app), and POSTs it to `/webhooks` with the correct `X-Hub-Signature`. `verify_signature` resolves `repository_owner` to `attacker-org`, fetches `attacker-org`'s `GitHubApp`, and the signature verifies successfully because it was computed with the correct (attacker-owned) secret. `MembershipHandler` then finds the pre-existing `shopify_developers` team by `github_id` and appends `attacker-login`'s `User` to its `members`.

This is a real authentication-bypass path because `User#authorized?` grants Shipit access to anyone whose `teams` intersects `Shipit.github_teams` [7](#0-6) , so an attacker with zero footprint in `shopify` can self-grant Shipit-wide authorization by exploiting a tenant they legitimately control.

None of the existing guards prevent this: `drop_unhandled_event` only checks the event type is handled, not who sent it; `verify_signature` verifies against a secret chosen from attacker-controlled data, so it authenticates the wrong tenant boundary rather than the team's actual owning org; the `ExplicitParameters` schema in `MembershipHandler` only validates types/presence, not that `organization.login` matches the existing `team.organization`; there is no `force_github_authentication`, `require_permission!`, or `User#authorized?` check in the webhook path at all — this is an unauthenticated ingestion endpoint by design (secured only by the HMAC), and that HMAC binding is what's broken here.

### Impact Explanation
A successful request causes a `Shipit::Membership` row to be created/persisted, linking the attacker's `User` (auto-created via `User.find_or_create_by_login!`) to a `Team` belonging to another tenant (`shopify`) that the attacker never authenticated as. If that team is in `Shipit.github_teams`, this directly grants the attacker `authorized?` == true across all of Shipit, i.e. authentication/authorization bypass into the entire application (dashboards, stack management, deploy triggers depending on further permission checks) — this matches the "escalation into `Shipit.github_teams` authorization" / "authentication bypass" Critical/High impact categories. The attack is repeatable against any team `github_id` the attacker can learn, across any number of tenants configured on the same Shipit instance, as long as the attacker controls at least one tenant's `webhook_secret`.

### Likelihood Explanation
Preconditions: (1) Shipit must be configured in multi-tenant mode with `Shipit.github` keyed by multiple organizations (confirmed supported by `github_app_config`/`github_default_organization` [8](#0-7) ); (2) the attacker must own/administer at least one of those configured GitHub orgs/apps, which is exactly the threat model given (an "unprivileged" attacker who can own a GitHub org and configure its webhook secret towards this Shipit instance); (3) the attacker needs the numeric `github_id` of the target team, which is generally discoverable via GitHub's public team/org APIs or via observed legitimate webhook traffic. No Shipit session, API token, or GitHub credentials belonging to the victim org are needed — only the attacker's own legitimately-issued secret for their own tenant. This is fully repeatable via simple scripted HTTP POSTs with no live GitHub interaction required for the proof.

### Recommendation
Bind webhook processing to the organization that was actually cryptographically verified, not to attacker-supplied body fields used a second time downstream. Concretely: pass the verified `repository_owner`/organization through to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, verified_organization: repository_owner) }`, and in `MembershipHandler#process` (and any other handler using `params.team.id` / similar cross-org identifiers) enforce `team.organization == verified_organization` before mutating, raising/dropping the event otherwise. `find_or_create_team!` should never silently reuse an existing `Team` whose `organization` differs from the organization whose secret verified the request.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb`-style setup (illustrative, no live GitHub):

```ruby
test "membership webhook signed by attacker-org cannot mutate a team belonging to shopify" do
  # Arrange: two tenants configured
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(attacker_github_app)
  Shipit.stubs(:github).with(organization: 'shopify').returns(shopify_github_app)
  attacker_github_app.stubs(:verify_webhook_signature).returns(true)  # attacker's own valid secret
  shopify_github_app.stubs(:verify_webhook_signature).returns(false) # never actually invoked

  shopify_team = shipit_teams(:shopify_developers) # existing Team, organization: 'shopify'

  body = {
    action: 'added',
    team: { id: shopify_team.github_id, name: shopify_team.name, slug: shopify_team.slug, url: shopify_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker-login' }
  }.to_json

  post shipit.webhooks_path, params: body, headers: {
    'X-Github-Event' => 'membership',
    'X-Hub-Signature' => 'sha1=irrelevant-because-stubbed',
    'Content-Type' => 'application/json'
  }

  assert_response :ok
  # Assert both sides of the binding: verifying org != team's owning org, yet mutation happened
  assert_equal 'attacker-org', JSON.parse(body)['organization']['login']
  assert_equal 'shopify', shopify_team.organization
  assert shopify_team.reload.members.exists?(login: 'attacker-login'),
    "attacker was added to shopify's team despite signature being verified by attacker-org's own secret"
end
```

This demonstrates the binding `verifying_org (attacker-org) != team.organization (shopify)` while the mutation (`Membership` creation) still occurs, confirming the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
