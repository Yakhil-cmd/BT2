### Title
Cross-organization team membership mutation via `team.id`-only lookup in `MembershipHandler#process` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the `Team` record solely by the numeric `github_id` from the webhook payload, and `find_or_create_team!`/`process` never checks that the requesting organization (whose secret verified the webhook) actually owns that team. An attacker controlling any organization onboarded to Shipit's GitHub App can forge a `membership` webhook, signed with their own org's secret, that references another organization's team by `github_id` and removes an arbitrary user's `Membership` row for that team.

### Finding Description
The binding that should hold is: `params.organization.login` (the org whose secret verified the webhook, via `Shipit.github(organization: repository_owner)` in `WebhooksController#verify_signature`, `app/controllers/shipit/webhooks_controller.rb:24-30`) `==` `team.organization` (the org that actually owns the team being mutated, `app/models/shipit/team.rb`).

Tracing the path:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('organization', 'login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`) and verifies the signature against `Shipit.github(organization: repository_owner)`'s secret — i.e., against the *attacker's own organization's* registered secret, since the attacker fully controls the `organization.login` field of their own forged payload.
- Once verified, `MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` (lines 38-43). This lookup is keyed **only** on `github_id`. If a `Team` row already exists for that `github_id` (belonging to the victim organization), it is returned as-is — the `organization` field is not compared against `params.organization.login` at all.
- `process` then executes `team.members.delete(member)` for `action == 'removed'` (line 30), deleting the `Membership` row between the resolved (victim) `Team` and the `User` resolved from `params.member.login`.

Nothing in the call chain re-checks organizational ownership of the team after signature verification. `verify_signature` only proves the payload's *stated* organization controls its own secret — it says nothing about which team the payload's `team.id` refers to. The two values (verifying org vs. team-owning org) are never compared, so the binding is broken exactly as claimed.

Exploit: an attacker whose own GitHub organization is installed with Shipit's GitHub App sends `POST /webhooks` with `X-Github-Event: membership`, a valid signature computed with their own org's webhook secret, `organization.login` = attacker's org, `team.id` = the victim's privileged team's `github_id` (learnable/guessable or via reconnaissance), `action: 'removed'`, and `member.login` = the victim operator's GitHub login. This deletes the `Membership` row for that operator on the victim team, deauthorizing them from any `Shipit.github_teams`-gated capability tied to that team.

### Impact Explanation
This allows one organization's webhook to mutate another organization's team roster — directly matching the in-scope "payload for one repository mutating another repository's ... team" impact category. If the targeted team maps into `Shipit.github_teams` (operator/authorization gating), the attacker can silently revoke a legitimate operator's authorization, and could similarly craft `action: 'added'` on the sibling path to grant membership to an attacker-controlled login (a separate but structurally identical bug in the same method), escalating into Shipit authorization. The action is repeatable for any known `github_id` of any team across any tenant using the same Shipit instance.

### Likelihood Explanation
Preconditions: attacker needs an organization onboarded to the same Shipit GitHub App instance (so `Shipit.github(organization: attacker_org)` resolves and can produce a validly-signed payload with their own secret), knowledge of the victim team's numeric `github_id`, and the victim login already having a `Membership` row for that team. No Shipit session, API token, or GitHub secret belonging to the victim org is required — only the attacker's own legitimately-issued webhook secret for their own org. This is a low-cost, fully repeatable attack limited only by discovery of the target `github_id`.

### Recommendation
In `find_or_create_team!`, require that an existing `Team` matched by `github_id` also has `organization == params.organization.login`, and reject/raise if they mismatch instead of silently reusing the victim's team. More generally, `MembershipHandler#process` should verify `team.organization == params.organization.login` before performing `add_member`/`members.delete`, mirroring the ownership check needed on the "added" path.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (conceptual addition)
test "removed action cannot delete membership on a team owned by a different organization" do
  victim_team = shipit_teams(:shopify) # organization: "shopify", github_id: 42
  operator = shipit_users(:walrus)
  Membership.create!(team: victim_team, user: operator)

  payload = {
    'action' => 'removed',
    'team' => { 'id' => victim_team.github_id, 'name' => 't', 'slug' => 't', 'url' => 'https://x' },
    'organization' => { 'login' => 'attacker-org' }, # signed with attacker-org's own secret
    'member' => { 'login' => operator.login },
  }

  assert Membership.exists?(team: victim_team, user: operator)
  Shipit::Webhooks::Handlers::MembershipHandler.new(payload).call
  # Binding check: attacker-org != victim_team.organization ("shopify")
  refute_equal 'attacker-org', victim_team.organization
  assert Membership.exists?(team: victim_team, user: operator),
    "membership should not be deletable by an unrelated organization's webhook"
end
```
This test bypasses `WebhooksController` (signature already assumed valid per attacker-controlled org) and directly demonstrates that `MembershipHandler#process` deletes the membership despite the organization mismatch, confirming the broken binding. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** app/models/shipit/team.rb (L1-59)
```ruby
# frozen_string_literal: true

module Shipit
  class Team < Record
    REQUIRED_HOOKS = %i[membership].freeze

    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user

    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false

    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
      end

      def find_team_on_github(organization, slug)
        gh_api = Shipit.github(organization:).api
        teams = Shipit::OctokitIterator.new(github_api: gh_api) { gh_api.org_teams(organization, per_page: 100) }
        teams.find { |t| t.slug == slug }
      rescue Octokit::NotFound
      end
    end

    def handle
      "#{organization}/#{slug}"
    end

    def add_member(member)
      members.append(member) unless members.include?(member)
    end

    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end

    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
  end
```
