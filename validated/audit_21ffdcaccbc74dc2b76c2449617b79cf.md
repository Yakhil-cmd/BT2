### Title
Cross-organization team-membership forgery via `MembershipHandler` github_id lookup - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `organization.login` (for events with no `repository` key, like `membership`), but `MembershipHandler` resolves the `Team` to mutate purely by the GitHub-assigned `team.id`, never re-checking that the team actually belongs to the organization whose secret authenticated the request. This breaks the binding "organization that authenticated == organization whose membership state is written," letting an operator of one Shipit-registered GitHub organization forge team-membership changes for a *different* Shipit-registered organization's team.

### Finding Description
`WebhooksController#verify_signature` determines the authenticating org like this: [1](#0-0) 
and the fallback for events without a `repository` key (such as `membership`) resolves purely to `organization.login`: [2](#0-1) 

Shipit explicitly supports hosting **multiple independent GitHub organizations from one instance**, each with its own `webhook_secret`: [3](#0-2) 

Once the signature is verified against the secret for `organization.login`, the payload is dispatched to `MembershipHandler`: [4](#0-3) 

The critical flaw is in `find_or_create_team!`: it looks the `Team` up **only by `github_id`**, and the block that sets `team.organization = params.organization.login` only executes when a *new* record is created (`find_or_create_by!` semantics). If a `Team` row with that `github_id` already exists — created earlier by a legitimate webhook from its real organization — the existing record (bound to the real organization) is returned unchanged, and the attacker-supplied `organization.login` is silently ignored for the membership mutation: [5](#0-4) 

`team.add_member(member)` is then called with `member` resolved purely from the attacker-controlled `member.login` field via `User.find_or_create_by_login!`: [6](#0-5) 

The binding broken: **the organization that authenticated the webhook (via its own `webhook_secret`) is never required to equal the organization the mutated `Team` actually belongs to.** An operator/admin of org A (who legitimately possesses org A's `webhook_secret` because they administer org A's GitHub App registered on this shared Shipit instance) can sign an arbitrary JSON body with `organization.login: "orgA"` (satisfying `verify_signature`) while setting `team.id` to the numeric GitHub team id of an authorization-relevant team belonging to org B, and `member.login` to their own (or any) GitHub login.

### Impact Explanation
`User#authorized?` grants full application access (viewing/deploying/locking any stack, managing API clients, etc.) to any user who is a member of a team listed in `Shipit.github_teams`: [7](#0-6) 

By forging a `membership` `added` event against a known `github_id` belonging to a target org's authorization team, an attacker escalates into `Shipit.github_teams` authorization for an organization/repository set they have no legitimate relationship with, then completes GitHub OAuth as themselves and gains authenticated access to that org's stacks — an unauthorized privilege escalation into the app's core authorization boundary. This matches the "High" impact category: "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Exploitation requires: (1) the shared Shipit instance manages more than one GitHub organization (a documented, supported configuration), (2) the attacker legitimately controls the GitHub App/webhook secret for at least one of those organizations, and (3) the attacker knows or can determine the numeric `github_id` of a target team in another org (obtainable if previously a member, via GitHub's team API, or by brute-forcing small integer ranges since GitHub team IDs are sequential). This is a plausible insider/cross-tenant scenario rather than a purely theoretical one, but it does depend on the multi-org deployment model and some knowledge of the target `github_id`.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that an existing `Team` record's `organization` matches `params.organization.login` before mutating membership (raise/ignore on mismatch), and/or scope the `find_or_create_by!` lookup by both `github_id` and `organization` rather than `github_id` alone.

### Proof of Concept
1. Configure/observe that the target Shipit instance manages two organizations, `orgA` (attacker-administered) and `orgB` (target), each with distinct `webhook_secret`s, per `config/secrets.development.shopify.yml`.
2. Attacker obtains `orgB`'s existing authorization team's GitHub `team.id` (e.g., previously observed, or brute-forced).
3. Attacker crafts a `membership` event payload:
```json
{
  "action": "added",
  "team": { "id": <orgB_team_github_id>, "name": "Developers", "slug": "developers", "url": "https://example.com" },
  "organization": { "login": "orgA" },
  "member": { "login": "attacker-github-login" }
}
```
4. Attacker computes `X-Hub-Signature` using `orgA`'s known `webhook_secret` over the raw JSON body (per `Shipit::Hook::DeliverySigner`/`GithubApp#verify_webhook_signature` logic), and POSTs to `/webhooks` with `X-Github-Event: membership`.
5. `verify_signature` resolves `repository_owner` to `"orgA"` and successfully verifies using orgA's secret.
6. `MembershipHandler#find_or_create_team!` looks up the existing `Team` by `github_id` (matching org B's team) and calls `team.add_member(User.find_or_create_by_login!("attacker-github-login"))`, adding the attacker to org B's authorization team.
7. Attacker logs in via GitHub OAuth as `attacker-github-login`; `User#authorized?` now returns true for org B's `Shipit.github_teams`, granting access to org B's stacks.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-44)
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
