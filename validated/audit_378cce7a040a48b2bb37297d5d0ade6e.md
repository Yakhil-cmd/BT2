### Title
Webhook organization binding bypass allows cross-tenant Team/Membership writes - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to verify a webhook body against using only `repository.owner.login` (falling back to `organization.login`), but `MembershipHandler` independently trusts `params.organization.login` and `params.team.id` to decide which `Team` row to create/find and mutate. Nothing in the request pipeline enforces that the organization whose secret verified the signature is the same organization named in the nested `organization` object, so an attacker who legitimately controls one tenant's GitHub App installation can forge a `membership` webhook that is signed with their own secret but names a victim organization's team, causing a `Membership` write against that victim team.

### Finding Description
The required binding is: `verified_org == mutated_org`, i.e. `repository_owner` (the org whose `webhook_secret` validated `request.raw_post`) must equal `params.organization.login` (the org whose `Team` gets created/mutated). The code never enforces this. [1](#0-0)  selects the verifying app via `Shipit.github(organization: repository_owner)` and checks the signature against that app's secret only. [2](#0-1)  defines `repository_owner` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — it reads only the top-level `repository.owner.login`. [3](#0-2)  shows `find_or_create_team!` using `params.team.id` and `params.organization.login` with no reference to, or comparison against, `repository_owner`.

Multi-tenant configuration is real and supported: `Shipit.github(organization:)` looks up a per-organization config (including a distinct `webhook_secret`) via `github_app_config`, and raises `GithubOrganizationUnknown` only if that organization isn't configured at all. [4](#0-3) 

Exploit flow: the attacker owns/administers `attacker-org`, which has the Shipit GitHub App installed and thus a configured `webhook_secret` known to them. They POST directly to `/webhooks` with header `X-Github-Event: membership` and a JSON body where `repository.owner.login = "attacker-org"` but `organization.login = "shopify"` and `team.id` set to a known/guessed GitHub team ID belonging to `shopify`. They sign the raw body with `attacker-org`'s own webhook secret. `verify_signature` computes `repository_owner` as `attacker-org`, fetches `Shipit.github(organization: 'attacker-org')`, and the HMAC check succeeds because it's genuinely their own secret. Control then reaches `MembershipHandler#process`, which calls `find_or_create_team!` — this looks up (or creates) a `Team` by `github_id: params.team.id` and, on find, immediately proceeds to `team.add_member(member)`, writing a `Membership` row for a team that was never established as belonging to the verified organization.

No existing guard catches this: `drop_unhandled_event` only checks that a handler exists for the event name; the `ExplicitParameters` schema in `MembershipHandler` only validates types/presence of `organization.login`, `team.id`, etc., not cross-field consistency with the verifying organization; there is no `force_github_authentication`, `User#authorized?`, or `require_permission!` call in this unauthenticated webhook path since it is intentionally public (signature is the only authentication mechanism), and that authentication is scoped to the wrong field.

### Impact Explanation
A successful request creates or mutates a `Team`/`Membership` record belonging to a different, unrelated GitHub organization than the one that authenticated the request — a payload signed by one tenant mutating another tenant's team/membership data. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is fully repeatable: the attacker can invoke this once per desired membership change and can target any team whose numeric `github_id` they know or guess, across any organization configured in the same multi-tenant Shipit instance. Team membership can influence downstream authorization surfaces (e.g., `Shipit.github_teams`), so this can also seed escalation into privileged team-based checks elsewhere in the app.

### Likelihood Explanation
This requires a Shipit deployment using the multi-organization `secrets.github` configuration schema (keyed by organization) where an attacker-controlled organization is one of the configured tenants with the Shipit GitHub App installed — a supported, documented configuration per `Shipit.github_organizations`/`github_app_config`. Given that precondition, the attack costs the attacker nothing beyond knowing their own webhook secret (which they legitimately possess as the installer of their own app) and a target team's numeric GitHub team ID (not secret, discoverable via the GitHub API/UI for any team they can see, or guessable since IDs are sequential). The request is a single unauthenticated HTTP POST, fully repeatable and scriptable.

### Recommendation
Enforce that the organization used to select/verify the webhook signature is the same organization referenced by any nested `organization`/`team` object consumed by handlers. Concretely, in `Shipit::WebhooksController`, after computing `repository_owner`, reject the request (422) if `params.dig('organization', 'login')` is present and differs from `repository_owner`, and pass the verified organization explicitly into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, verified_organization: repository_owner) }`. Update `MembershipHandler#find_or_create_team!` to assert `params.organization.login == verified_organization` before creating/mutating any `Team`, raising/dropping the event otherwise.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (minitest, no live GitHub):
```ruby
test ":membership from attacker-org cannot mutate shopify's team" do
  Shipit.stubs(:secrets).returns(stub(
    github: {
      'attacker-org' => { webhook_secret: 'attacker-secret' },
      'shopify' => { webhook_secret: 'shopify-secret' }
    }
  ))

  shopify_team = shipit_teams(:shopify_developers)

  forged_payload = {
    action: 'added',
    team: { id: shopify_team.github_id, name: shopify_team.name, slug: shopify_team.slug, url: shopify_team.api_url },
    organization: { login: 'shopify' },        # victim org, mutated
    member: { login: 'attacker-controlled-user' },
    repository: { owner: { login: 'attacker-org' } } # org whose secret actually verifies
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', forged_payload)}"

  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  # Left side of the binding: verified org == 'attacker-org' (attacker's own secret)
  # Right side: mutated org == 'shopify' (via params.organization.login)
  assert_no_difference -> { Membership.where(team: shopify_team).count } do
    post :create, body: forged_payload, as: :json
  end
  assert_response :ok # currently succeeds and writes the membership — assert_no_difference should fail today, proving the bug
end
```
This test signs the body with the attacker's own org secret while naming `shopify` as the mutated organization/team; today it will write a `Membership` for `shopify_team` (the `assert_no_difference` assertion fails), demonstrating that `repository_owner`'s verified organization is never reconciled with `params.organization.login` before the team mutation.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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
