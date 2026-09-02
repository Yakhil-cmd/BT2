### Title
Cross-organization team-membership hijack via unbound `team.id` in `MembershipHandler` grants unauthorized `Shipit.github_teams` access - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit.github_teams` (`lib/shipit.rb:256`) is the authorization boundary the whole engine relies on: `Authentication#force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb:20-34`) checks `current_user.authorized?`, and `User#authorized?` (`app/models/shipit/user.rb:80-82`) grants access if the user is a member of one of these configured `Team` records. Team membership is populated exclusively from the GitHub `membership` webhook, processed by `MembershipHandler`. The webhook signature is verified per-organization (`WebhooksController#verify_signature`), but the code that mutates team membership trusts a payload field (`team.id`) that is never cross-checked against the organization that was actually authenticated for that request, breaking the equality "organization whose secret authenticated the request == organization whose team is written."

### Finding Description
`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) resolves which GitHub App/organization config to use for HMAC verification purely from attacker-supplied JSON: [1](#0-0) 
`repository_owner` falls back to `params.dig('organization', 'login')` for events like `membership` that have no `repository` key. This means the signature is only proof that *some* configured organization's secret produced this exact payload — not that the payload's other fields (like a GitHub team ID) actually belong to that organization.

`MembershipHandler#process` then uses the payload to add/remove a member from a `Team`, resolved by GitHub's global `team.id` alone: [2](#0-1) 
`Team.find_or_create_by!(github_id: params.team.id)` only sets `team.organization = params.organization.login` inside the creation block; if a `Team` row with that `github_id` already exists (created earlier from a legitimate webhook belonging to a *different* organization), the existing record is returned unchanged and `params.organization.login` is never validated against it. `team.add_member(member)` (`app/models/shipit/team.rb:41-43`) then unconditionally appends `params.member.login` (also attacker-supplied and independently resolved via `User.find_or_create_by_login!`) to that team's `memberships`.

Root-cause equality broken: **organization authenticated by `verify_signature` (via `params.organization.login`) ≠ organization owning the `Team` whose membership is mutated (matched only by global `github_id`, from the same untrusted payload)**. Analogous to the report's `depositFor`, where the function trusted a caller-supplied identity (`_for`) instead of binding the action to the verified actor (`msg.sender`); here the handler trusts a caller-supplied `team.id`/`organization.login` pair instead of verifying that the `Team` record it mutates actually belongs to the organization whose secret authenticated the webhook.

### Impact Explanation
Any customer/tenant who legitimately administers a Shipit-integrated GitHub organization (and therefore knows or controls their own org's webhook secret, exactly as they would when wiring up their own webhook to Shipit) can forge a `membership` event: `organization.login` set to their own org (so `verify_webhook_signature` succeeds with their own secret), but `team.id` set to the numeric GitHub ID of a `Team` that is listed in `Shipit.github_teams` and belongs to an unrelated, privileged organization, and `member.login` set to their own (or any) GitHub username. This inserts that user as a member of the privileged `Team`, and `User#authorized?` will then grant them full authenticated access to Shipit (deploy, rollback, merge, view secrets in task output, etc.) — a direct escalation into `Shipit.github_teams` authorization, which the rules explicitly classify as High impact.

### Likelihood Explanation
The only precondition is administrative control (or knowledge of the configured webhook secret) of *any one* organization onboarded into Shipit's multi-tenant `github:` config — not a privileged Shipit account, GitHub App private key, or `ApiClient` token. Given Shipit's design explicitly supports multiple independent organizations sharing one deployment (as seen in `config/secrets.development.shopify.yml` and `TOP_LEVEL_GH_KEYS` handling in `lib/shipit.rb:170-200`), this is a realistic deployment topology, and GitHub team IDs used for the target `Shipit.github_teams` are discoverable (they are visible via the GitHub API/UI to team members, or via prior legitimate `membership` webhook deliveries logged/observed by any team member of the target org).

### Recommendation
When resolving or creating a `Team` in `MembershipHandler#find_or_create_team!`, verify that the resolved `Team#organization` matches `params.organization.login` (the same identity that `verify_signature` authenticated) before allowing `add_member`/`delete` to proceed, and reject/log mismatches instead of silently reusing the existing record.

### Proof of Concept
1. Shipit is configured with two tenants, e.g. `orgA` and `orgB`, each with its own `webhook_secret` in `config/secrets.*.yml` (per `lib/shipit.rb:170-200`).
2. `Shipit.github_teams` includes a team belonging to `orgB` (e.g. `orgB/admins`), already persisted with `github_id = 999`.
3. An attacker who administers `orgA` (and thus knows `orgA`'s webhook secret) crafts:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "admins", "slug": "admins", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "orgA" },
  "member": { "login": "attacker" }
}
```
4. Signs the raw body with `orgA`'s known `webhook_secret` and POSTs it to `/github/webhooks` with `X-Github-Event: membership` and the correct `X-Hub-Signature`.
5. `verify_signature` resolves `Shipit.github(organization: 'orgA')` and succeeds (valid signature for `orgA`).
6. `MembershipHandler#find_or_create_team!` finds the existing `Team` with `github_id: 999` (which actually belongs to `orgB`) and does not check `organization.login`.
7. `team.add_member(User.find_or_create_by_login!('attacker'))` adds `attacker` to `orgB/admins`.
8. `attacker` logs in via GitHub OAuth; `User#authorized?` now returns `true` because they belong to a `Shipit.github_teams` team, granting full Shipit access. [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
