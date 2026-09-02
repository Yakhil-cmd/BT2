### Title
Cross-tenant Team hijack via github_id-only lookup in `find_or_create_team!` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id`, ignoring the `organization.login` asserted in the current webhook payload. Because signature verification is scoped per-organization via `repository_owner` falling back to `organization.login`, an attacker who owns their own GitHub organization (with a legitimately configured Shipit webhook secret) can send a validly-signed `membership` webhook claiming `organization.login = 'attacker-org'` but reusing the `github_id` of a pre-existing `shopify`-owned `Team` row, causing that team's membership to be mutated by an unrelated tenant.

### Finding Description
The broken binding is: `Team#organization` (set once at row creation) `==` `params.organization.login` (asserted on every subsequent verified webhook for that team). This invariant is not enforced.

Code path: `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . For a `membership` event there is no `repository` key, so `repository_owner` resolves to `attacker-org`, and the signature is verified using `attacker-org`'s own webhook secret via `github_app.verify_webhook_signature` [2](#0-1) . This succeeds because the attacker legitimately controls `attacker-org` and its webhook secret — no `shopify` secret is needed.

The controller then dispatches to `MembershipHandler.call(params)`, which invokes `find_or_create_team!`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [3](#0-2) 

`find_or_create_by!` looks up by `github_id` alone. If a `Team` row with that `github_id` already exists (created earlier via a legitimate `shopify` webhook, with `organization = 'shopify'`), the block is never executed and `organization` is never re-checked against `params.organization.login`. The returned `team` is the pre-existing `shopify` team despite the payload asserting `attacker-org`. `process` then calls `team.add_member(member)` [4](#0-3) , appending an attacker-controlled `User` to `shopify`'s `Team`, via `Team#add_member` [5](#0-4) .

No other guard intervenes: the `ExplicitParameters` schema only validates types/presence of `organization.login`, `team.id`, etc. [6](#0-5) ; it never cross-checks `organization.login` against the resolved `Team#organization`. `Shipit.github_teams`, which grants authorization, is derived from `Team.find_or_create_by_handle` results and membership on these `Team` rows [7](#0-6) , so mutating team membership here has direct authorization impact if `shopify`'s team is one of the configured `Shipit.github_teams`.

### Impact Explanation
A single crafted, validly-signed webhook from an attacker-owned GitHub organization can add (or remove) members on any pre-existing `Team` row belonging to a different tenant (e.g., `shopify`), purely by guessing/observing that team's `github_id` (which is not secret — GitHub team IDs are visible via API/UI to anyone with read access, and are sequential/enumerable). If the targeted `Team` is part of `Shipit.github_teams` used for authorization, this is a cross-tenant authorization escalation: an attacker-controlled GitHub login gets added as a member of a team that grants access to Shipit. This matches "escalation into `Shipit.github_teams` authorization" and "a payload for one repository/organization mutating another's team," i.e., Critical/High severity as defined. The attack is repeatable against any `Team` row whose `github_id` the attacker can learn, is not limited to `shopify`, and requires no privileged credentials, GitHub App secrets, or Shipit session.

### Likelihood Explanation
Preconditions: the attacker must control a GitHub organization with a Shipit GitHub App/webhook installed (any external org can typically configure this in a self-serve fashion depending on `Shipit.github` multi-org config), and must know the `github_id` of the target team (obtainable via GitHub's public/authenticated Teams API for orgs the attacker has any visibility into, or via prior legitimate interactions with the target org, or brute force since IDs are sequential integers). No `shopify` secrets, sessions, or maintainer status are required — only the attacker's own verifiable webhook secret. This is a low-cost, repeatable attack limited only by knowledge of the target's numeric team ID.

### Recommendation
Scope the lookup by both `github_id` and `organization` (or by `repository_owner`/`organization.login` derived from the verified payload), rejecting or logging when a `github_id` collision is found under a mismatched organization, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login
    raise ArgumentError, "Team github_id #{params.team.id} does not belong to organization #{params.organization.login}"
  end
  team || Team.create!(github_id: params.team.id, organization: params.organization.login) do |t|
    t.github_team = params.team
  end
end
```
Additionally, `verify_signature` should not fall back to `organization.login` without also validating that the `Team`/`Repository` referenced in the payload actually belongs to that organization.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership from a different org cannot mutate another org's team by reusing github_id" do
  shopify_team = shipit_teams(:shopify_developers) # organization == 'shopify', has a github_id

  @request.headers['X-Github-Event'] = 'membership'
  attacker_payload = {
    action: 'added',
    team: { id: shopify_team.github_id, name: 'X', slug: 'x', url: 'http://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker' }
  }.to_json

  # stub verify_signature success for attacker-org only (their own secret)
  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  assert_difference -> { Membership.count }, 1 do
    post :create, body: attacker_payload, as: :json
    assert_response :ok
  end

  new_membership = Membership.last
  # BEFORE fix: this passes, proving the binding is broken
  assert_equal shopify_team.id, new_membership.team_id
  assert_equal 'shopify', shopify_team.reload.organization
  # despite payload asserting organization.login == 'attacker-org'
end
```
This demonstrates `Team#organization` ('shopify') diverging from the verified payload's `organization.login` ('attacker-org') while the mutation still lands on the `shopify` team.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
