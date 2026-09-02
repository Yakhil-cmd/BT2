Confirmed: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [1](#0-0) , so becoming a member of a privileged `Team` row (matched by id, independent of `organization`) directly flips `authorized?` to true. This confirms the escalation impact claimed.

### Title
Cross-organization team membership escalation via `github_id`-only lookup in `MembershipHandler#find_or_create_team!` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the signing organization/secret using `repository_owner`, which for a `membership` event falls back to `params.dig('organization', 'login')` — the payload's own organization, which for an attacker is their own org with their own legitimately-held webhook secret. `MembershipHandler#find_or_create_team!` then resolves the target `Team` by `github_id` alone via `Team.find_or_create_by!(github_id: params.team.id)`, ignoring `params.organization.login` on the found branch, letting an attacker who controls "evil-org" name an existing `team.id` belonging to a different, privileged organization and add themselves to it.

### Finding Description
The binding that must hold is: **the organization whose secret verified the payload == the organization owning the team that gets mutated**, i.e. `verify_signature`'s `repository_owner` must equal the `organization` field stored on the `Team` record being modified. This breaks because:

1. `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) . A real GitHub `membership` event payload has no top-level `repository` key (it's an org-level event), so `repository_owner` resolves to `organization.login` from the payload — a value fully controlled by whoever sends the webhook.
2. `Shipit.github(organization: repository_owner)` looks up that organization's own `webhook_secret` via `github_app_config` [3](#0-2)  and `verify_webhook_signature` checks the HMAC against that org's secret [4](#0-3) . An attacker who owns "evil-org" (multi-org configured) legitimately possesses that secret and signs successfully.
3. `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [5](#0-4) . The block only runs on **creation**; if a `Team` row with that `github_id` already exists (belonging to a different, trusted organization), `find_or_create_by!` returns the existing record unmodified, silently ignoring the organization mismatch.
4. `team.add_member(member)` then appends the attacker's `User` to that pre-existing, unrelated team's `memberships` [6](#0-5) .
5. `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [1](#0-0) ; since `Shipit.github_teams` includes the targeted team, the attacker now satisfies this check.

None of the existing guards prevent this: `verify_signature` only proves the payload was signed by *some* configured organization, not the one owning the referenced team; `ExplicitParameters` only validates types/presence, not organization consistency; and no `Team`-ownership check exists in `find_or_create_team!`.

### Impact Explanation
A successful request adds an arbitrary attacker-controlled GitHub login as a member of any `Team` already present in `Shipit.github_teams` (i.e., any team ever used for authorization), regardless of which organization actually owns it. Since `User#authorized?` gates access to the entire Shipit application (`app/controllers/concerns/shipit/authentication.rb`), this is a direct authentication/authorization bypass — escalation into `Shipit.github_teams` authorization, matching the High/Critical impact categories described. The attack is repeatable against every `github_id` known or guessable by the attacker (team IDs are often enumerable/public via GitHub's API) and works across tenants in any multi-org Shipit deployment.

### Likelihood Explanation
Preconditions: Shipit configured for multiple GitHub organizations (`github_app_config`/multi-org secrets), and `Shipit.github_teams` populated with at least one team whose `github_id` the attacker knows. The attacker only needs to control (own/administer) one arbitrary GitHub organization with its own GitHub App/webhook configured in Shipit — a low, realistic bar for a public or semi-public Shipit instance — and send one POST to `/webhooks` with a forged `membership` payload signed with their own valid secret. No access to the victim organization's secrets, tokens, or Shipit session is required, satisfying the "unprivileged attacker" constraint.

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), or explicitly verify that `Team.find_by(github_id: params.team.id)&.organization == params.organization.login` before mutating, raising/rejecting on mismatch. Additionally, `WebhooksController#repository_owner` should not trust the org-supplied `organization.login` for signature-organization selection without cross-checking it against the team's actually stored organization once resolved.

### Proof of Concept
Minitest plan (no live GitHub, all within `test/`):
```ruby
test "cross-org membership webhook cannot hijack a team belonging to another organization" do
  trusted_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: 42
  assert_not_equal 'evil-org', trusted_team.organization

  # configure a second org "evil-org" with its own webhook_secret in secrets.github
  # (use test/dummy/config/secrets_double_github_app.yml style config)
  payload = {
    action: 'added',
    team: { id: trusted_team.github_id, name: trusted_team.name, slug: trusted_team.slug, url: trusted_team.api_url },
    organization: { login: 'evil-org' },
    member: { login: 'attacker' }
  }.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', evil_org_webhook_secret, payload)

  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { Team.where(organization: 'evil-org').count } do
    post :create, body: payload, as: :json
  end
  assert_response :ok

  # BEFORE: trusted_team.organization ('shopify') != payload organization.login ('evil-org')
  # AFTER (bug): membership still created against trusted_team
  attacker = User.find_by(login: 'attacker')
  assert trusted_team.members.reload.include?(attacker), "attacker was added to a team it should not have access to"
  assert attacker.authorized?, "attacker gained authorization via a team belonging to another organization"
end
```
This asserts the equality `trusted_team.organization == 'evil-org'` is false both before and after, yet the membership/authorization state changes anyway, proving the binding violation.

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
