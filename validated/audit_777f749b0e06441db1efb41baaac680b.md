## Title
Team lookup by `github_id` alone in `MembershipHandler#process` lets a webhook legitimately signed for one configured GitHub organization deauthorize a member of a *different* organization's team - (`app/models/shipit/webhooks/handlers/membership_handler.rb`)

## Summary
`MembershipHandler#find_or_create_team!` matches an existing `Team` solely on `params.team.id` (an attacker-controlled integer in the payload) and never re-validates that `params.organization.login` matches the `Team#organization` already stored for that `github_id`. In a multi-organization Shipit deployment (`Shipit.github_app_config`/`secrets.github` keyed by org), a webhook payload that is validly HMAC-signed for organization B (because Shipit picks the signing secret via `repository_owner`, which for a `membership` event is `params.dig('organization','login')`) can still name `team.id` equal to a team that actually belongs to organization A, causing `team.members.delete(member)` to run against A's team/membership record.

## Finding Description
The claimed binding — "deletion of a `Membership` row == an actual removal event GitHub emitted for that `team_id`/`member.login` pair" — is broken as follows:

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` selects which app/secret to verify against using `repository_owner`, which falls back to `params.dig('organization', 'login')` [1](#0-0) [2](#0-1) . This means the signature is only proof that *some* configured GitHub organization (whichever `organization.login` names) emitted the event — not that the named `team.id` belongs to that organization.
- `MembershipHandler#find_or_create_team!` looks up an existing `Team` by `github_id: params.team.id` only; it sets `organization` from the payload solely on first creation, and performs no check that `params.organization.login` equals the pre-existing `Team#organization` on subsequent events [3](#0-2) .
- `process` then executes `team.members.delete(member)` for `'removed'` unconditionally once the (mismatched) team is resolved [4](#0-3) .
- `Shipit.github` supports genuinely distinct per-organization app configs (`github_app_config`, `secrets.github` keyed by org) [5](#0-4) , so this is not a purely single-tenant deployment assumption — multi-org configuration is a supported, documented mode.

Exploit precondition: the attacker must control (own/administer) a *second* GitHub organization that is itself configured in the same Shipit instance's `secrets.github` (i.e., a legitimate customer/organization with its own webhook secret registered), and must know/guess the numeric `github_id` of the victim team belonging to organization A (`Shipit.github_teams`). With that, the attacker generates a real `membership` `removed` webhook from their own org B (fully valid HMAC signature, since GitHub itself will sign it, or since the attacker owns org B's webhook secret), naming `team.id` = A's team id and `member.login` = the victim. Shipit verifies the signature against org B's secret (valid), then the handler deletes the membership row for A's team/victim pair.

Existing guards do not prevent this: `verify_signature` only authenticates "an event came from *a* configured organization," not "this event's team belongs to that organization" [6](#0-5) ; the `ExplicitParameters` schema in the handler only validates types/presence, not cross-field org/team consistency [7](#0-6) ; `Team.find_or_create_by!` has no organization-equality check on the existing record [3](#0-2) .

## Impact Explanation
A member of `Shipit.github_teams` loses their `Membership` row and thus fails `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [8](#0-7) , denying them deploy/rollback/merge authorization in Shipit until GitHub resyncs membership (e.g., via `refresh_members!` or a real re-add event). This is a cross-tenant integrity violation: an event legitimately signed for organization B mutates state (`Membership`) belonging to organization A. This matches "High" (escalation/deauthorization impacting `Shipit.github_teams` authorization) rather than the RCE/token-exfiltration tier of "Critical," since no code execution, credential leak, or unauthorized deploy directly results — only removal of authorization for a specific victim.

## Likelihood Explanation
This requires: (1) a Shipit deployment using the multi-organization `secrets.github` schema with at least two configured, unrelated organizations (one attacker-controlled), and (2) the attacker knowing the target team's numeric `github_id`. Team IDs are not typically secret (visible to team members, sometimes via public API for org teams depending on visibility), but the attacker must operate a *second* legitimately-registered GitHub organization/app within the same Shipit instance — this is a real but non-trivial precondition, plausible in a SaaS-style multi-tenant Shipit deployment but not in typical single-org self-hosted setups (which are the common case, based on `github_default_organization` backward-compatibility logic) [9](#0-8) .

## Recommendation
In `find_or_create_team!`, when the `Team` already exists, verify `team.organization == params.organization.login` (case-insensitively, matching `find_or_create_by_handle`'s downcasing) and raise/drop the event if it doesn't match, rather than silently reusing the pre-existing record regardless of the payload's claimed organization.

## Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb`, illustrative — actual file may need creating under permitted paths):

```ruby
test "removed event with mismatched organization does not affect binding" do
  org_a_team = shipit_teams(:shopify)  # belongs to organization "shopify", github_id fixed
  member = users(:walrus)
  org_a_team.add_member(member)
  assert_equal 1, Membership.where(team: org_a_team, user: member).count

  # Forge payload: organization.login = "attacker-org" (a different, configured org),
  # but team.id equal to org_a_team.github_id
  payload = {
    action: 'removed',
    team: { id: org_a_team.github_id, name: org_a_team.name, slug: org_a_team.slug, url: org_a_team.api_url },
    organization: { login: 'attacker-org' },  # does NOT equal org_a_team.organization ("shopify")
    member: { login: member.login }
  }

  assert_not_equal payload[:organization][:login], org_a_team.organization

  Shipit::Webhooks::Handlers::MembershipHandler.new(payload).call

  assert_equal 0, Membership.where(team: org_a_team, user: member).count
  assert_not member.reload.authorized?
end
```

This demonstrates: `payload[:organization][:login] != org_a_team.organization` both before and after handler execution (the equality claimed by the binding never held), yet the `Membership` row is deleted and `authorized?` flips to `false` — confirming the handler does not enforce organization/team consistency.

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
