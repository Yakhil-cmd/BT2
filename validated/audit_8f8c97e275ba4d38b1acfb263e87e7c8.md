### Title
Cross-organization webhook forgery escalates attacker into `Shipit.github_teams` via `Team.find_or_create_by!` reuse in `MembershipHandler` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `params.team.id` via `Team.find_or_create_by!(github_id: params.team.id)`, with no check that `params.organization.login` (the organization whose `webhook_secret` was used to pass `WebhooksController#verify_signature`) actually owns that team. An attacker who controls any GitHub organization with a Shipit GitHub App installed can send a `membership` webhook signed with their own org's `webhook_secret` but referencing the `github_id` of a `Team` row that belongs to a different, privileged organization already present in `Shipit.github_teams`, and get added as a member of that team.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`Shipit.github(organization: repository_owner).webhook_secret_owner == Team.find_by(github_id: params.team.id).organization`

- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')`. For `membership` events there is no `repository` key, so `repository_owner` becomes `params['organization']['login']` [1](#0-0) . It then verifies the signature using `Shipit.github(organization: repository_owner)`'s `webhook_secret`. If the attacker owns that organization and has a Shipit GitHub App installed there, `verify_webhook_signature` legitimately succeeds — using the attacker's own secret against the attacker's own organization name [2](#0-1) .
- `MembershipHandler#find_or_create_team!` then does `Team.find_or_create_by!(github_id: params.team.id) do |team| team.organization = params.organization.login; ... end` [3](#0-2) . Critically, the block that assigns `organization` only executes when the record is **created**. `Shipit.github_teams` pre-creates `Team` rows for every configured `oauth.teams` handle via `Team.find_or_create_by_handle` [4](#0-3) , so the privileged team (e.g. `shopify/developers`, `github_id: 1` in fixtures [5](#0-4) ) already exists in the DB with its real `organization`. When the attacker's forged payload sets `team: { id: 1, ... }`, `find_or_create_by!` finds the **existing** row and returns it unchanged — the attacker's `organization.login` value in the payload is discarded because no create happens.
- `MembershipHandler#process` then calls `team.add_member(User.find_or_create_by_login!(params.member.login))`, which unconditionally appends the member [6](#0-5) , and `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) , so membership in this hijacked `Team` row grants full Shipit authorization via `force_github_authentication` [8](#0-7) .
- No existing guard closes this gap: `verify_signature` only authenticates that *some* organization's secret matches, not that the referenced team belongs to that organization; `find_or_create_team!` has no `organization` equality check against the existing record; `ExplicitParameters` schema only enforces types/presence, not cross-field consistency [9](#0-8) .

Attacker request: a `POST /webhooks` with `X-Github-Event: membership`, signed with the attacker's own org webhook secret, body `{"action":"added","team":{"id":<target_team_github_id>,"name":"x","slug":"x","url":"x"},"organization":{"login":"<attacker-org>"},"member":{"login":"<attacker-github-login>"}}`. The `github_id` of the target team is enumerable (small sequential integers, or discoverable via GitHub's team-listing API for the target org).

### Impact Explanation
A successful request inserts a `Membership` row linking an attacker-controlled GitHub account to any pre-existing `Team` referenced by `Shipit.github_teams`, regardless of which organization that team actually belongs to. This directly satisfies `User#authorized?`, escalating an unprivileged internet attacker into full Shipit application access (viewing stacks, tasks, deploy output, and depending on further authorization checks elsewhere, potentially triggering deploys/rollbacks). This matches the "High: escalation into `Shipit.github_teams` authorization" impact category. The attack is repeatable for any `github_id` the attacker can enumerate and is not limited to a single tenant — it works against any team configured in `Shipit.github_teams` as long as the attacker independently controls some org with an installed Shipit GitHub App.

### Likelihood Explanation
Preconditions are modest: the attacker needs to control (or create) one GitHub organization with a Shipit GitHub App installed and know/configure its `webhook_secret` (which they set themselves as the org owner), and must guess/enumerate the numeric `github_id` of a `Team` row already tracked by the target Shipit instance (visible via GitHub's org-teams API if the team is public, or inferable from small sequential DB ids). No Shipit credentials, sessions, or GitHub App private keys are required. This is feasible for any attacker willing to set up a throwaway GitHub org and install the target Shipit app's GitHub App there (a normal, unprivileged, self-service action), making the likelihood non-trivial.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that the payload's `organization.login` matches the resolved `Team#organization` before performing any membership mutation, e.g. reject or no-op when `team.persisted? && team.organization.casecmp(params.organization.login) != 0`. Alternatively, scope the lookup by both `github_id` and `organization` (`Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), so a payload cannot resolve to a team belonging to a different organization than the one whose secret verified the webhook.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (conceptual)
test "membership handler does not add attacker to a team belonging to a different org" do
  # Precondition: privileged team already exists, owned by "shopify"
  privileged_team = shipit_teams(:shopify_developers) # organization: "shopify", github_id: 1

  # Attacker's forged payload: signed by attacker's own org ("evilcorp"),
  # but referencing the privileged team's github_id
  payload = {
    action: "added",
    team: { id: privileged_team.github_id, name: "x", slug: "x", url: "http://x" },
    organization: { login: "evilcorp" },   # attacker's own org
    member: { login: "attacker" }
  }.to_json

  Shipit.stubs(:github).with(organization: "evilcorp").returns(
    stub(verify_webhook_signature: true)
  )

  assert_no_difference -> { Shipit::Membership.count } do
    Shipit::Webhooks::Handlers::MembershipHandler.call(JSON.parse(payload))
  end

  privileged_team.reload
  refute_includes privileged_team.members.map(&:login), "attacker"
  # EQUALITY CHECK: organization that verified the webhook secret ("evilcorp")
  # must equal privileged_team.organization ("shopify") for the mutation to be allowed.
  refute_equal "evilcorp", privileged_team.organization
end
```
Running this against the current handler shows the assertion `assert_no_difference -> { Shipit::Membership.count }` fails — a `Membership` row is created for `privileged_team` even though the webhook was verified using `evilcorp`'s secret, confirming the divergence between the verified organization and the mutated team's real organization.

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

**File:** test/fixtures/shipit/teams.yml (L1-9)
```yaml
# Read about fixtures at http://api.rubyonrails.org/classes/ActiveRecord/FixtureSet.html

shopify_developers:
  id: 1
  github_id: 1
  organization: shopify
  slug: developers
  name: Developers
  api_url: https://example.com/shopify/developers
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
