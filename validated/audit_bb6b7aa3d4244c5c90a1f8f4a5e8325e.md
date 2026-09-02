### Title
Membership webhook authorizes on a different organization than the one it writes to, allowing cross-organization `Shipit.github_teams` escalation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using `repository_owner`, but `Shipit::Webhooks::Handlers::MembershipHandler` writes team membership using a completely different field, `params.organization.login`, from the same payload. Because these two fields are independently controlled inside one attacker-supplied, self-signed JSON body, an attacker who legitimately controls the webhook secret for *any* organization configured in a multi-org Shipit deployment can forge a signed `membership` payload that is authenticated against their own org but whose effects (team creation / membership add) are applied to an arbitrary victim organization's team, including teams that gate `Shipit.github_teams` authorization.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes the signing organization like this: [1](#0-0) [2](#0-1) 

`repository_owner` prefers `repository.owner.login`, falling back to `organization.login` only when `repository` is absent. The chosen organization determines which `GitHubApp` (and therefore which `webhook_secret`) is used to validate `X-Hub-Signature` — this is by design to support the documented multi-org configuration (`lib/shipit.rb#github`, `docs/setup.md` "Using Multiple Github Applications").

However, `MembershipHandler` — the handler invoked for the `membership` event — never looks at `repository` at all. It parses and acts exclusively on `params.organization.login`, `params.team`, and `params.member`: [3](#0-2) 

Because the HMAC signature covers the raw JSON body as a whole, an attacker cannot tamper with a legitimately-issued payload from GitHub. But nothing stops an attacker who *administers their own GitHub organization/App integrated with the same Shipit instance* (a normal, unprivileged relationship to that org — they are not required to have any access to the victim org or its secrets) from **constructing their own JSON body from scratch**, including:
- `"repository": {"owner": {"login": "<attacker-org>"}}` — used only to select the signature-verification secret,
- `"organization": {"login": "<victim-org>"}` — used only by `MembershipHandler` to decide which `Team.organization` to create/mutate,
- an arbitrary `team.id` (`github_id`) and `member.login` of their choosing,

then signing that body with the webhook secret for `<attacker-org>` (which they legitimately possess) and submitting it with `X-Github-Event: membership`.

`verify_signature` resolves `repository_owner` to `<attacker-org>`, fetches `Shipit.github(organization: "<attacker-org>")`, and successfully verifies the signature using the attacker's own secret. The request is never checked for consistency between `repository.owner.login` and `organization.login`. `MembershipHandler#process` then runs using `params.organization.login == "<victim-org>"`: [4](#0-3) 

`find_or_create_team!` will create a brand new `Team` (with an attacker-chosen `github_id`) scoped to `organization: "<victim-org>"` if none exists with that `github_id`, or match an existing one — and `team.add_member(member)` adds the attacker-controlled `User` (auto-vivified via `User.find_or_create_by_login!`) as a member.

This is a break of exactly the binding class called out in scope: *"an organization that authenticated versus the repository/org that is written."* The signature check binds trust to `repository_owner`; the write path binds mutation to a distinct, independently-supplied `organization.login` field from the same unsigned-relationship payload.

### Impact Explanation
`User#authorized?` gates all engine access on team membership matching `Shipit.github_teams` (the configured OAuth-authorized teams): [5](#0-4) 

and `Team.organization`/`github_id` are exactly the fields this forged webhook lets the attacker set for a newly created or matched `Team` row. If the deployment configures `Shipit.github_teams` to reference a team in `<victim-org>` (the normal configuration, per `docs/setup.md`), the attacker can:
1. Discover (or guess) the numeric `github_id` and `slug` of the authorized team, or create a team with a `github_id` colliding with a team that legitimately exists (the code does `find_or_create_by!(github_id: ...)`, so if a `Team` row for the real authorized team already exists in Shipit's DB with a known `github_id`, the attacker's forged event matches it directly), and
2. Add themselves (`member.login` = their own GitHub login) to that team via the `added` action.

Once the `Membership`/`Team` row exists, `current_user.authorized?` returns true for that attacker on their next OAuth login, granting them full authenticated access to the Shipit instance — including deploy, rollback, lock/unlock, and merge actions on stacks bound to that org. This matches the explicitly listed High-impact category: *"escalation into `Shipit.github_teams` authorization."*

The attacker only needs legitimate control of a webhook secret for **some** org onboarded into the same multi-tenant Shipit instance (their own org) — not the victim org's secret, GitHub App private key, or any Shipit credential, session, or API client token. This satisfies the "unprivileged attacker" requirement.

### Likelihood Explanation
Likely only in multi-organization Shipit deployments (`lib/shipit.rb#github_app_config`, as documented under "Using Multiple Github Applications"), where more than one organization's GitHub App is configured against the same Shipit instance and where at least one of those orgs is one the attacker administers themselves (e.g. a partner/vendor org, a sandbox org set up for testing, or any org onboarded by a different team within the same company). This is a realistic operational pattern for the multi-org feature, and requires no compromise of the victim org's secrets, no repository write access on the victim, and no interaction with any Shipit-issued credential.

### Recommendation
In `Shipit::Webhooks::Handlers::MembershipHandler` (and any other org-scoped handler), verify that the organization the mutation is being applied to matches the organization whose secret authenticated the request (i.e., cross-check `params.organization.login` against the `repository_owner`/authenticating-organization value computed in `WebhooksController#verify_signature`, and reject the event otherwise). More generally, `WebhooksController` should pass the authenticated organization down to handlers and each handler should assert equality between the field(s) it mutates and the authenticated org, rather than trusting an independently-parsed field from the same payload.

### Proof of Concept
Preconditions: Shipit configured with `github: { AttackerOrg: {...}, VictimOrg: {...} }` (multi-org config), attacker knows `AttackerOrg`'s `webhook_secret` (they administer `AttackerOrg`'s GitHub App/webhook), and `Shipit.github_teams` includes a team belonging to `VictimOrg` with a known `github_id`.

```json
{
  "action": "added",
  "team": { "id": <victim_team_github_id>, "name": "x", "slug": "x", "url": "https://example.com" },
  "organization": { "login": "VictimOrg" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "AttackerOrg" } }
}
```

1. Compute `X-Hub-Signature: sha1=HMAC_SHA1(AttackerOrg_webhook_secret, raw_body)`.
2. `POST /github_webhooks` (webhook endpoint) with header `X-Github-Event: membership`, the body above, and the computed signature.
3. `verify_signature` resolves `repository_owner => "AttackerOrg"`, fetches `Shipit.github(organization: "AttackerOrg")`, verifies successfully with the attacker's own secret.
4. `MembershipHandler#process` runs with `params.organization.login == "VictimOrg"`, matches/creates the `Team` for `github_id == <victim_team_github_id>`, and adds `attacker-github-login` as a member via `team.add_member(member)`.
5. Attacker logs into Shipit via GitHub OAuth; `current_user.authorized?` now returns `true` because `teams` includes the row just created, granting full access to stacks under `Shipit.github_teams` authorization. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
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
      end
    end
  end
end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end
```
