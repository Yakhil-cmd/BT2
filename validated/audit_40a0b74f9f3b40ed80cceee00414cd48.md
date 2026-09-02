### Title
Membership webhook team lookup skips organization ownership check, allowing cross-organization team escalation - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` purely by the attacker-suppliable `github_id` integer and never re-validates that the webhook's `organization.login` matches the `organization` column already stored on that `Team` record before calling `team.add_member(member)`. Because webhook signature verification is itself keyed off attacker-controlled payload data (the `organization`/`repository.owner.login` field), an attacker who legitimately controls any organization onboarded to the same Shipit instance can sign a `membership` event under their own org while reusing the `team.id` of a `Team` that belongs to a different, privileged organization, causing themselves to be added as a member of that team.

### Finding Description
The broken binding is: `params.organization.login == team.organization` for the `Team` record identified by `params.team.id` must hold before `team.add_member(member)` executes. In reality:

- `find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [1](#0-0) . The block that sets `organization` is **only executed on record creation**; if a `Team` row with that `github_id` already exists (e.g. created by a prior legitimate `membership` hook from the real owning org), the existing `organization` column is left untouched regardless of what `organization.login` is in the new payload.
- `process` then unconditionally calls `team.add_member(member)` for `action == 'added'` with no comparison between `params.organization.login` and `team.organization` [2](#0-1) .
- `Team#add_member` performs no ownership check either [3](#0-2) .
- Webhook authenticity is checked in `WebhooksController#verify_signature`, which derives `repository_owner` from the payload itself (`params.dig('repository','owner','login') || params.dig('organization','login')`) and fetches the corresponding `GitHubApp` secret via `Shipit.github(organization: repository_owner)` [4](#0-3) [5](#0-4) . This only proves the request was validly signed for *whatever organization name is embedded in the payload*, not that this organization is the one that owns the referenced `team.id`.

Exploit flow: an attacker who administers any organization that has been legitimately onboarded to the same Shipit instance (and therefore knows that organization's webhook secret, since org owners configure/know their own webhook secrets) crafts a `membership` `added` event where `organization.login` is set to their own org (so `verify_signature` passes with a correctly computed HMAC), but `team.id` is set to the numeric `github_id` of a `Team` belonging to a different, privileged organization already present in Shipit's DB (e.g., learned from GitHub's public teams API before the org went private, or from a prior legitimate membership). Because the `Team` record already exists, `find_or_create_by!`'s block does not run, `team.organization` remains the victim org, and `team.add_member(attacker_user)` executes anyway — adding the attacker to the privileged team.

This bypasses the intended guarantee because the signature check validates payload authenticity for an organization *name string* controlled by the attacker, while the team-mutation logic keys off a numeric ID with no re-check of ownership against that same string.

### Impact Explanation
A successful request adds the attacker's `User` to a `Team` record that may be included in `Shipit.github_teams`, which gates `force_github_authentication` used by all `ShipitController` subclasses. This is a direct authorization escalation into the whole Shipit application for the attacker, without any legitimate membership in the victim GitHub organization/team. The action is repeatable for any `Team` whose numeric `github_id` the attacker can learn, and reusable across further `added`/`removed` membership manipulations once the attacker controls a signing organization.

### Likelihood Explanation
Exploitation requires: (1) the attacker to control (as owner/admin) at least one GitHub organization that is configured/onboarded with the target Shipit deployment (so they can compute a valid `X-Hub-Signature` for that org's webhook secret — a plausible scenario in multi-tenant Shipit deployments where multiple orgs/teams share one instance), and (2) knowledge of a target `Team`'s numeric `github_id` (obtainable via GitHub's public API before privatization, or from prior legitimate membership). Both are consistent with the stated attacker capability of "emitting webhooks from a repository/org they own." No Shipit or GitHub Ellen operator secrets are required beyond the attacker's own organization's webhook secret, which they possess by definition of owning that org's webhook configuration.

### Recommendation
In `find_or_create_team!`, when a `Team` already exists for the given `github_id`, verify that `params.organization.login` equals the existing `team.organization` before proceeding; if they differ, reject/raise rather than silently reusing the stale team record. Additionally, `MembershipHandler#process` should not call `team.add_member`/`team.members.delete` unless `team.organization == params.organization.login` (or equivalently `repository_owner`) is confirmed, closing the gap where the signature-verified organization can diverge from the mutated team's actual organization.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
class MembershipHandlerTest < ActiveSupport::TestCase
  test "cross-organization membership escalation" do
    victim_team = Team.create!(
      github_id: 4242,
      organization: 'victim-org',
      name: 'core',
      slug: 'core',
      api_url: 'https://api.github.com/teams/4242'
    )
    attacker_user = User.find_or_create_by_login!('attacker')

    payload = {
      'action' => 'added',
      'team' => { 'id' => 4242, 'name' => 'core', 'slug' => 'core', 'url' => victim_team.api_url },
      'organization' => { 'login' => 'attacker-org' }, # forged signature scope, NOT victim-org
      'member' => { 'login' => 'attacker' }
    }

    Shipit::Webhooks::Handlers::MembershipHandler.call(payload)

    assert_equal 'victim-org', victim_team.reload.organization
    assert victim_team.members.include?(attacker_user) # attacker escalated into victim-org's team
  end
end
```
This test calls `MembershipHandler.call` directly (bypassing HTTP/signature verification layer, which is orthogonal to the logic bug), asserting that despite `organization.login` mismatching `victim_team.organization`, the attacker is added as a member — confirming the missing binding check.

### Citations

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
