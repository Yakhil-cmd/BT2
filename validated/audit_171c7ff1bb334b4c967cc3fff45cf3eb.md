### Title
Cross-organization `Team` hijack via `MembershipHandler`'s unscoped `github_id` lookup allows unauthorized escalation into `Shipit.github_teams` authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
This is an analog of the "excessive authority to a single executor" bug class: the `membership` webhook handler trusts a payload field (`team.id`) that is scoped only by the webhook's HMAC signature, but the record it mutates (`Shipit::Team`) is looked up **globally** by that numeric ID, without re-checking that the signing organization actually owns that team. In a multi-organization Shipit deployment, any organization that Shipit trusts enough to receive signed webhooks from can be used to overwrite membership of a `Team` belonging to a *different* organization, including a team listed in `Shipit.github_teams` that gates authorization for the whole app.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook against based on the organization named in the payload itself: [1](#0-0) [2](#0-1) 

This correctly authenticates that the payload was signed by *some* organization's configured webhook secret (Shipit explicitly supports multiple GitHub organizations, each with its own `webhook_secret`, per `docs/setup.md`). However, this binding only proves "the payload came from organization X" — it does not prove "the `team` record referenced in the payload belongs to organization X."

`MembershipHandler#find_or_create_team!` finds (or creates) the `Team` purely by the numeric `github_id` supplied in the payload, ignoring the `organization.login` for the lookup key: [3](#0-2) 

Since GitHub team IDs are integers that are visible via the public GitHub API (`/orgs/{org}/teams`) or the Shipit UI/API for any org a user is a member of, an attacker who controls (or is a legitimate maintainer of) **any** GitHub organization configured in this Shipit deployment can:
1. Look up the `github_id` of a `Team` record belonging to a different, privileged organization (e.g., the org listed in `Shipit.github_teams`).
2. Have their own organization deliver a `membership` webhook — which they fully control and can sign with their own org's legitimate `webhook_secret` — with `action: 'added'`, `team.id` set to the target team's `github_id`, and `member.login` set to their own GitHub login.
3. `WebhooksController#verify_signature` verifies the signature successfully (it is a valid signature — just for the wrong org's data).
4. `MembershipHandler#find_or_create_team!` finds the *existing* target `Team` by `github_id` (matching regardless of organization) and `team.add_member(member)` adds the attacker as a member.
5. `User#authorized?` checks membership against `Shipit.github_teams` by team `id`, not by re-verifying which org actually owns the team: [4](#0-3) 

The equality that should hold but is broken: `organization that authenticated the webhook == organization that owns the Team record being mutated`. Instead, the code only asserts `organization that authenticated == organization named in the (attacker-controlled) payload`, and separately, `Team looked up by github_id (global, unscoped)`.

### Impact Explanation
This escalates an attacker (who need only control one trusted-but-unprivileged GitHub organization configured in the Shipit instance) into membership of a `Team` that gates `Shipit.github_teams` authorization, per the explicit High-severity criterion "escalation into `Shipit.github_teams` authorization." Once added, `User#authorized?` returns true for that user, granting them access to the entire Shipit application, including stacks, deploys, task triggering, and repository management, without a legitimate invitation or membership in the actual privileged GitHub organization.

### Likelihood Explanation
This requires a multi-organization Shipit configuration (explicitly documented and supported in `docs/setup.md`), and requires the attacker to control (or have webhook-configuration access to) at least one of the organizations trusted by that Shipit instance — not the target's privileged organization. GitHub team IDs are discoverable via the GitHub API for teams the attacker can see, or may be guessable/enumerable as sequential integers. No `ApiClient` token, session, or GitHub App private key is required — only the ability to trigger (or replay) a correctly-signed `membership` webhook from an org already onboarded to the Shipit instance.

### Recommendation
Scope the `Team` lookup in `MembershipHandler#find_or_create_team!` by both `github_id` **and** `organization: params.organization.login`, rejecting or ignoring events where an existing team's stored `organization` does not match the webhook's authenticated organization. More generally, any webhook handler that mutates a record identified by a GitHub-supplied numeric ID should also assert that the record's stored organization/owner matches the organization that the signature was verified against.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `victim-org` (whose team `Shopify Developers`, `github_id: 999`, is included in `Shipit.github_teams`) and `attacker-org` (attacker-controlled, also configured in Shipit's `github` secrets as a legitimate second organization).
2. Attacker discovers `github_id: 999` for the `victim-org` team via GitHub's public/authenticated API.
3. Attacker sends (or configures their own org's GitHub App to send) a `membership` webhook to `/webhooks`, signed with `attacker-org`'s real `webhook_secret`:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "Shopify Developers", "slug": "developers", "url": "https://api.github.com/teams/999"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker-login"}
}
```
4. `WebhooksController#verify_signature` succeeds (valid signature for `attacker-org`).
5. `MembershipHandler#find_or_create_team!` finds the existing `Team` with `github_id: 999` (the victim's team) and adds `attacker-login` as a member.
6. Attacker logs into Shipit via GitHub OAuth; `User#authorized?` now returns true because they belong to a team in `Shipit.github_teams`, granting full application access. [5](#0-4) [6](#0-5) [4](#0-3)

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
