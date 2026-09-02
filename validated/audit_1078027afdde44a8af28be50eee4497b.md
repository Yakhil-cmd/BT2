### Title
Cross-organization webhook forgery grants team membership without verifying signing org matches team's organization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` never checks that the organization which signed the incoming `membership` webhook is the same organization that owns the target `Team` record. `WebhooksController#verify_signature` only proves the request was signed with the webhook secret of `repository_owner` (i.e. `organization.login` from the same JSON body), but for any pre-existing `Team` (looked up solely by `github_id`), that verified organization is never compared to `team.organization`. An attacker who controls any GitHub organization onboarded into the same multi-tenant Shipit instance can sign a `membership` webhook with their own valid secret and target any other organization's `Team` by `github_id`, adding themselves (or anyone) as a member.

### Finding Description
The broken binding is: `verified_org (from HMAC signature check in WebhooksController#verify_signature) == team.organization (of the Team row being mutated in MembershipHandler)`.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) resolves `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and validates the signature using `Shipit.github(organization: repository_owner)`. This only proves "this body was signed by org `repository_owner`'s configured webhook secret" — it says nothing about which `Team` row the body claims to reference. [1](#0-0) [2](#0-1) 

- `MembershipHandler#process` and `#find_or_create_team!` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-43`) resolve the target team purely by `Team.find_or_create_by!(github_id: params.team.id)`. The block that sets `team.organization = params.organization.login` only executes when ActiveRecord *creates* a new record; for any `github_id` that already exists in the `teams` table, the found `Team`'s `organization` is used unmodified and is never compared to `params.organization.login` or to the org that passed signature verification. [3](#0-2) 

Root cause: webhook provenance is checked once, at the org level, using attacker-controlled `organization.login`/`repository.owner.login`; the handler that actually mutates state trusts an attacker-controlled `team.id` with no re-validation that the verified organization is the owner of that team.

Attacker's exact request: the attacker must control (or be an admin of) some GitHub organization "attacker-org" that is legitimately configured in this Shipit instance's `secrets.github` (multi-tenant deployment), so they know/can set that org's real webhook secret. They send `POST /webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with `attacker-org`'s secret, and a body:
```json
{
  "action": "added",
  "team": { "id": <github_id of an existing privileged Team, e.g. shopify_developers>, "name": "x", "slug": "x", "url": "x" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "mallory" }
}
```
`verify_signature` passes because it only checks `attacker-org`'s secret against the body. `MembershipHandler#find_or_create_team!` finds the pre-existing Team row (owned by a different, privileged organization) by `github_id` alone and adds `mallory` as a member — no code path ever compares `attacker-org` to that team's `organization` column.

Existing guards checked and why they don't help: `verify_signature` (org-signature only, no team-ownership check), `drop_unhandled_event` (irrelevant, `membership` is handled), the `ExplicitParameters` schema on `MembershipHandler` (only type-checks fields, doesn't enforce org/team binding), `force_github_authentication`/`User#authorized?` (these run for UI requests, not webhooks, and `authorized?` is exactly what this bug lets an attacker fraudulently satisfy).

### Impact Explanation
The attacker can write a `Membership` row associating an arbitrary GitHub login (including their own Shipit `User`) with any pre-existing `Team`, regardless of which organization the webhook was actually signed for. If that `Team` is one of `Shipit.github_teams` (`lib/shipit.rb:256-258`, used by `User#authorized?` at `app/models/shipit/user.rb:80-82`), this is a direct authorization bypass: the attacker's Shipit user becomes "authorized" and passes `force_github_authentication`, gaining access to the whole application (stacks, deploys, tasks) that `Shipit.github_teams` gates. This is repeatable for any `Team#github_id` known to the attacker and works across every organization tenant hosted by the same Shipit instance, matching the "High - escalation into `Shipit.github_teams` authorization" category. [4](#0-3) [5](#0-4) 

### Likelihood Explanation
Requires Shipit configured for multiple GitHub organizations (`github_app_config`/multi-org `secrets.github`) where the attacker controls or administers at least one onboarded organization (thus knows/controls its webhook secret) and can discover a target `Team`'s GitHub team `id` (numeric GitHub team IDs are often discoverable via GitHub's API/UI or by observing prior legitimate webhook traffic). No Shipit session, API token, or the target org's own secret is needed. Given those preconditions, the attack is cheap, repeatable, and requires only a single crafted HTTP POST per membership grant/revoke.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that the signing organization matches the found `Team#organization` for existing teams, and reject (or ignore) the event if they differ, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
  raise ArgumentError, "Organization mismatch" unless team.organization.casecmp?(params.organization.login)
  team
end
```
Additionally, `WebhooksController#verify_signature` should not allow `organization.login` alone (attacker-controlled, and self-referential with the org used for signature verification) to stand in for verified provenance of unrelated `team.id` values.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":membership forges membership on a team owned by a different organization than the signer" do
  target_team = shipit_teams(:shopify_developers) # organization: 'shopify'
  assert_equal 'shopify', target_team.organization

  request.headers['X-Github-Event'] = 'membership'
  # Attacker's own org "attacker-org" signs successfully; no knowledge of shopify's secret needed.
  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  payload = {
    action: 'added',
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'mallory' }
  }.to_json

  assert_difference -> { Membership.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  assert target_team.reload.members.exists?(login: 'mallory')
  # Binding claimed to hold: verified_org ('attacker-org') should equal team.organization ('shopify') -- it does not, yet the write succeeded.
  refute_equal 'attacker-org', target_team.organization
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
