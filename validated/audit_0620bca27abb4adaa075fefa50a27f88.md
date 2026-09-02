### Title
Cross-tenant team-membership mutation via unbound `team.id` in `MembershipHandler#process` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the target `Team` purely from the attacker-supplied `params.team.id` (GitHub team ID) with no check that the team's stored `organization` matches the organization whose webhook secret validated the request. In a multi-org Shipit deployment, an operator of Org A (who legitimately knows Org A's own configured `webhook_secret`) can sign an arbitrary payload naming Org B's team ID and remove any of Org B's members from that team.

### Finding Description
The intended binding is: `signing_organization (repository_owner used in Shipit.github(organization:))` == `team.organization (the real GitHub owner of params.team.id)`. Nothing in the code enforces this.

- `WebhooksController#verify_signature` selects the `GitHubApp` — and therefore the `webhook_secret` — solely from `repository_owner`, which is read straight from the payload (`params.dig('repository','owner','login') || params.dig('organization','login')`), then calls `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) . `verify_webhook_signature` is a plain HMAC-SHA1 check against that one org's `webhook_secret` — it never inspects `team.id` or cross-references any other field in the body [2](#0-1) .
- Each org in a multi-tenant Shipit config has its own independent `webhook_secret` set up by whoever configured that org's GitHub App/webhook — i.e. Org A's admin legitimately knows Org A's secret [3](#0-2) .
- `MembershipHandler#process` then does `team = find_or_create_team!`, which looks the `Team` up (or creates it) by `github_id: params.team.id` only — with no comparison of `team.organization` to `repository_owner`/`params.organization.login` [4](#0-3) .
- For `action == 'removed'`, it directly runs `team.members.delete(member)` where `member` is resolved from the attacker-supplied `member.login` via `User.find_or_create_by_login!` [5](#0-4) .

**Attack**: Attacker controls/administers Org A (already integrated into Shipit as a legitimate tenant, so they know Org A's `webhook_secret`). They send:
```json
{
  "action": "removed",
  "team": { "id": <Org B's privileged team github_id>, "name": "...", "slug": "...", "url": "..." },
  "organization": { "login": "org-a" },
  "member": { "login": "victim-operator" },
  "repository": { "owner": { "login": "org-a" } }
}
```
signed with Org A's HMAC secret over the raw body. `verify_signature` succeeds because it only validates against Org A's own secret and Org A's own name in the payload, both of which the attacker controls/knows. `find_or_create_team!` then finds Org B's actual `Team` row (matched only by `github_id`, not by organization) and `team.members.delete(member)` removes the victim's membership from a team they do not administer.

This bypasses `verify_signature` (only checks signature validity for the claimed org, not that the claimed org owns the referenced team), `drop_unhandled_event` (membership is a handled event), and the `ExplicitParameters` schema (only requires shape/types of fields, not cross-field organizational consistency) [6](#0-5) .

### Impact Explanation
If the removed member is a required team member for `Shipit.github_teams`, their `authorized?` check (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) can flip from true to false, deauthorizing a legitimate operator from all Shipit actions gated on team membership (merges, deploys, rollbacks) [7](#0-6) . This is a cross-tenant mutation: a payload signed and originated by Org A alters authorization data belonging to Org B, satisfying "a payload for one repository/org mutating another's team." This requires multi-org (`secrets.github` keyed by multiple organizations) configuration — a supported and documented mode [8](#0-7) ; single-org deployments are not affected in the same cross-tenant sense (there'd be nothing to cross into). The attack is repeatable against any team whose numeric `github_id` the attacker can learn.

### Likelihood Explanation
Requires: (1) Shipit configured with multiple onboarded GitHub organizations, (2) attacker controls one onboarded org's webhook secret (a legitimate but low-trust tenant), and (3) attacker knows/discovers the target team's numeric `github_id` (GitHub team IDs are opaque integers, not secret but not always exposed either — obtainable via GitHub API calls the attacker may have access to for public/discoverable teams, or by observing prior legitimate `membership` payloads). Given those preconditions, the exploit is a single crafted, self-signed HTTP POST with no interaction from Org B or the victim.

### Recommendation
In `MembershipHandler#process`/`find_or_create_team!`, verify that the resolved `Team#organization` equals the organization associated with the currently-verified webhook (i.e., `repository_owner`/`params.organization.login` used to select the `GitHubApp`), and reject (no-op or error) the event if they don't match, rather than blindly trusting `team.id` as a global, org-agnostic key. Pass the verified organization from the controller into the handler and assert equality before performing `add_member`/`members.delete`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test, conceptual)
test ":membership from org A cannot mutate org B's team" do
  org_b_team = shipit_teams(:shopify_developers) # belongs to organization 'shopify'
  victim = shipit_users(:walrus)
  org_b_team.add_member(victim)

  # Configure/verify signature succeeds for org A ('the-a-team' style config)
  request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'removed',
    team: { id: org_b_team.github_id, name: org_b_team.name, slug: org_b_team.slug, url: org_b_team.api_url },
    organization: { login: 'org-a' },
    member: { login: victim.login },
    repository: { owner: { login: 'org-a' } }
  }.to_json

  Shipit.github(organization: 'org-a').expects(:verify_webhook_signature).returns(true)

  assert_no_difference -> { org_b_team.memberships.count } do
    post :create, body: payload, as: :json
  end
  assert org_b_team.members.reload.include?(victim), "victim membership must survive an org-A-signed payload"
end
```
Assert both sides of the binding: `team.organization` ('shopify') must equal the organization that produced a valid signature ('org-a') before any mutation is permitted; currently they diverge and the mutation proceeds.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
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
