### Title
Membership webhook team lookup keyed solely on `github_id` lets a valid webhook from *any* configured GitHub organization grant Shipit-team membership on a *different* organization's team - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` exclusively by `params.team.id` (the numeric GitHub team id), never checking that `params.organization.login` matches the team's stored `organization`. Signature verification in `WebhooksController#verify_signature` only proves the payload was signed by *some* organization's configured `webhook_secret`, not that this organization owns the team named in the payload. An attacker who legitimately controls (and can genuinely sign webhooks for) any GitHub organization configured in Shipit can therefore add an arbitrary GitHub login as a member of a completely unrelated, privileged `Shipit.github_teams` team belonging to a different organization.

### Finding Description
The binding that should hold is:
`Membership.exists?(team: T, user: U)` (in Shipit's DB) `⇔` GitHub's org API reports `U` as an actual member of `T.handle` for `T.organization`.

This binding is broken because team resolution ignores the organization entirely:

```ruby
# app/models/shipit/webhooks/handlers/membership_handler.rb:38-43
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [1](#0-0) 

`Team.find_or_create_by!(github_id:)` only assigns the block (which sets `organization`) when *creating* a new record. If a `Team` row with that `github_id` already exists — which is exactly the case for every team surfaced through `Shipit.github_teams`, since those rows are pre-created via `Team.find_or_create_by_handle` at config load time — the existing row is returned unchanged, and `params.organization.login` from the forged payload is never compared against it. [2](#0-1) [3](#0-2) 

`WebhooksController#verify_signature` picks which organization's secret to verify against purely from the payload itself:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

For a `membership` event there is no top-level `repository` key, so `repository_owner` resolves to `params.organization.login`. Signature verification therefore only proves "this request was HMAC-signed with the `webhook_secret` configured for the organization named in `params.organization.login`" — it says nothing about the organization that actually owns `params.team.id`. Shipit explicitly supports per-organization webhook secrets (`config/secrets.*.yml` multi-org block), so an attacker who is a legitimate administrator of *their own* configured org (org B) genuinely knows org B's `webhook_secret` and can produce a valid `X-Hub-Signature` for any payload, including one whose `team.id` field names a team that actually belongs to org A.

Exploit flow:
1. Attacker discovers the numeric `github_id` of a team in `Shipit.github_teams` (public/discoverable via GitHub's org teams API on org A, or leaked from Shipit's forbidden-page team list — `Authentication#force_github_authentication` even echoes `team_handles` in the 403 body). [5](#0-4) 
2. Attacker POSTs to `/webhooks` with `X-Github-Event: membership`, `organization.login = "org-b"` (their own org), `team.id = <org A's real team github_id>`, `member.login = "attacker_login"`, `action = "added"`, signed with org B's genuine `webhook_secret`.
3. `verify_signature` passes (signature matches org B's secret for org B's claimed payload).
4. `MembershipHandler#process` runs: `find_or_create_team!` returns the *existing* privileged Team row (matched on `github_id` alone), `User.find_or_create_by_login!('attacker_login')` creates/fetches the attacker's `Shipit::User`, and `team.add_member(member)` inserts a `Membership` row binding attacker to the privileged team. [6](#0-5) 
5. `User#authorized?` now returns true for the attacker, since it only checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`. [7](#0-6) 
6. `force_github_authentication` no longer 403s the attacker. [5](#0-4) 

None of the listed guards catch this: `verify_signature`/`GitHubApp#verify_webhook_signature` validate signature authenticity per-organization but never cross-check the payload's internal `team`/`organization` consistency; `ExplicitParameters` (`params do ... end` in `MembershipHandler`) only enforces types/presence, not cross-field integrity; there is no `require_permission!` or model validation on `Team` that ties `github_id` to `organization` at write time (`Team` has no uniqueness/consistency validation shown for `github_id` + `organization`). [8](#0-7) 

### Impact Explanation
An attacker with legitimate (self-administered) access to only one configured GitHub organization in a multi-org Shipit deployment can grant themselves (or any arbitrary GitHub login they choose) membership of a `Shipit.github_teams` team that actually belongs to a different, unrelated organization, bypassing `User#authorized?` and thus `force_github_authentication`. This is an authorization-bypass into the privileged `Shipit.github_teams` set (matches the High/Critical category "escalation into `Shipit.github_teams` authorization" / "authentication bypass"). The attack is repeatable for any team whose `github_id` is discoverable, and once membership is added the attacker retains full authenticated access to every controller gated only by `force_github_authentication` until an operator notices and removes the bogus `Membership` row.

### Likelihood Explanation
Requires: (1) Shipit configured with at least one `Shipit.github_teams` entry, (2) a multi-organization Shipit deployment (or any scenario where the attacker genuinely knows a `webhook_secret` accepted by `Shipit.github`), and (3) knowledge of the target team's numeric `github_id` (obtainable via GitHub's public org teams API or the leaked team-handle list on the 403 page). Given these engine-level facts (per-org webhook secrets are a documented, supported configuration, and `github_id` lookup is unscoped), the attack requires no privileged Shipit role and is a single crafted HTTP POST.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` AND `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify that `repository_owner`/`params.organization.login` used for signature verification actually matches the organization stored on the resolved `Team` before calling `team.add_member`/`team.members.delete`. Reject the event (422/log) on mismatch.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership from org B's genuinely-signed webhook can add a member to org A's privileged team" do
  org_a_team = shipit_teams(:shopify_developers) # belongs to organization "shopify", github_id already set
  Shipit.stubs(:github_teams).returns([org_a_team])

  payload = {
    action: 'added',
    team: { id: org_a_team.github_id, name: org_a_team.name, slug: org_a_team.slug, url: org_a_team.api_url },
    organization: { login: 'org-b' }, # attacker's own, unrelated org
    member: { login: 'attacker_login' }
  }.to_json

  @request.headers['X-Github-Event'] = 'membership'
  # Simulate org-b's genuine webhook_secret producing a valid signature for org-b
  Shipit.github(organization: 'org-b').stubs(:verify_webhook_signature).returns(true)

  assert_difference -> { Shipit::Membership.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  attacker = Shipit::User.find_by(login: 'attacker_login')
  # BROKEN BINDING: attacker is now a member of org A's team despite never being verified via org A's GitHub API
  assert org_a_team.members.include?(attacker)
  assert attacker.authorized? # true -- should be false since attacker was never a real GitHub member of org A's team
end
```
This demonstrates the two sides of the equality diverge: `Membership.exists?(team: org_a_team, user: attacker)` is `true` in Shipit's DB, while GitHub's actual org API for `shopify/developers` never listed `attacker_login` as a member — the binding the question describes is indeed violated.

### Citations

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
