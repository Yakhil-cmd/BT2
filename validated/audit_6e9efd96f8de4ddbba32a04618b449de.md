### Title
Cross-tenant team-membership forgery in `MembershipHandler#process` grants unauthorized `Shipit.github_teams` access - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to verify against based on the payload's own `organization.login` field, which is fully attacker-controlled for `membership` events (no `repository` key is present). `MembershipHandler#find_or_create_team!` then looks up the target `Team` purely by the attacker-supplied numeric `team.id` (`github_id`), with no check that the signing organization actually owns that team, so an operator of any org with a legitimately configured GitHub App in this multi-tenant Shipit instance can forge a membership-`added` event that grants themselves membership in a `Team` belonging to a completely different organization.

### Finding Description
The broken binding: a `Membership` row (`team_id`, `user_id`) is supposed to mean "GitHub reported that `user` is a member of `team`, as attested by `team.organization`'s own webhook secret." Concretely this should be enforced as:
`team.organization == verified_signing_organization`

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` via `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and calls `Shipit.github(organization: repository_owner)` to verify `X-Hub-Signature` [2](#0-1) . For a `membership` event the payload has no `repository` key, so `repository_owner` is entirely the attacker-supplied `organization.login`.
2. `Shipit.github(organization:)` resolves the per-org `GitHubApp` config from `secrets.github` [3](#0-2) , and `verify_webhook_signature` checks the HMAC against that org's own `webhook_secret` [4](#0-3) . If `organization.login = 'attacker-org'` and the attacker legitimately controls a GitHub App/webhook for `attacker-org` configured in this multi-tenant Shipit instance, the signature check passes with the attacker's own secret.
3. `MembershipHandler#process` then does `team = find_or_create_team!` which runs `Team.find_or_create_by!(github_id: params.team.id) { ... }` [5](#0-4) . The creation block (which sets `team.organization`) only executes on first creation; if a `Team` with that `github_id` already exists (e.g., a legitimate team from a different, victim organization already tracked in Shipit), it is returned unchanged regardless of the payload's `organization.login`.
4. `team.add_member(member)` is then called unconditionally for `action == 'added'` [6](#0-5) , inserting a `Membership` row for the attacker's `User` into the victim team.
5. `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) ; since `Shipit.github_teams` is the configured allow-list of `Team` records [8](#0-7) , if the victim team's id is in that list, the attacker instantly becomes `authorized?`.

Existing guards do not catch this: `verify_signature`'s organization resolution is by design per-tenant (correct for legitimate single-tenant traffic), but nothing cross-checks that the *team* referenced in the payload actually belongs to the *organization* that signed the payload. `find_or_create_team!`'s lookup key (`github_id`) is global across all organizations in the same Shipit database, which is precisely what breaks the isolation between tenants.

### Impact Explanation
An attacker who controls any one organization with a legitimately configured GitHub App/webhook in this multi-tenant Shipit deployment can add themselves (or any known GitHub login) to a `Team` belonging to a different, unrelated organization purely by guessing/observing that team's numeric GitHub team ID (which is not secret — obtainable via the GitHub API, past webhook deliveries, or brute force of small integers). If that team is part of `Shipit.github_teams`, the attacker's `User#authorized?` becomes `true`, granting them full access to the Shipit UI/API for stacks/tasks that require team authorization — this is a cross-tenant authorization escalation, matching the "High: escalation into `Shipit.github_teams` authorization" category. It is repeatable for any team ID and requires no compromise of any Shipit or victim-org secret.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured in the multi-organization mode (`github:` keyed by org, per `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`), the attacker's own org must be one of the configured tenants (with a legitimately owned GitHub App/webhook), and `Shipit.github_teams` must reference at least one `Team` whose `github_id` the attacker can determine. Attacker cost is low: create/use their own already-configured GitHub App webhook, and send one crafted `membership` `added` payload with a guessed/known `team.id`. This is fully repeatable and requires no privileged Shipit credentials.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that the payload's `organization.login` matches the found team's stored `organization` before allowing any mutation (`add_member`/`delete`); reject (or re-key the lookup) on mismatch, e.g., scope the lookup by `github_id` **and** `organization`, or explicitly compare `team.organization.casecmp?(params.organization.login)` and raise/drop the event otherwise.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership from an unrelated but legitimately-signed org cannot add members to a foreign team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', existing github_id
  attacker_org = 'attacker-org'

  Shipit.github(organization: attacker_org).stubs(:verify_webhook_signature).returns(true)

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: attacker_org },
    member: { login: 'attacker-login' }
  }.to_json

  assert_no_difference -> { victim_team.reload.members.count } do
    post :create, body: payload, as: :json
  end

  attacker = User.find_by(login: 'attacker-login')
  refute attacker&.authorized?
end
```
Before the fix this test fails: `Membership.count` for `victim_team` increases by 1 and `attacker.authorized?` returns `true` if `victim_team` is included in `Shipit.github_teams`, proving the cross-tenant escalation.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
