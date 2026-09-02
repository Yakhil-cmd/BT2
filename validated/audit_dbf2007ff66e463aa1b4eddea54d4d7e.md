### Title
Webhook signature verification silently bypassed for unconfigured organizations, allowing unauthenticated forgery of `membership` events that grant `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` fails open — returning `true` — whenever the target organization has no `webhook_secret` configured, and the organization used for that check is selected directly from the unverified, attacker-controlled request body. This lets an unauthenticated attacker forge any webhook event, including `membership`, which is processed with no further authorization check.

### Finding Description
`WebhooksController#verify_signature` picks which org's GitHub App config to use for verification straight from the incoming JSON, before any signature has been validated: [1](#0-0) [2](#0-1) 

That config is then handed to `GitHubApp#verify_webhook_signature`: [3](#0-2) 

The first line, `return true unless webhook_secret`, makes signature verification an opt-in control rather than a default-secure one — exactly the same bug class as the referenced Sui report, where a defensive control (traffic-control DOS protection) only activated if operators explicitly configured it, so anyone who didn't configure it ran unprotected. Here, `docs/setup.md` even documents the webhook secret as "(optional)": [4](#0-3) 

Because `repository_owner` (used to pick the org/secret) is read from the same untrusted payload that is later processed by handlers, and because that field is never itself covered by any signature check when the resolved org has no secret, an attacker can name any organization in the payload. If that organization is not configured with a `webhook_secret` (e.g., an org Shipit doesn't manage, or one whose operator simply left it blank as the docs allow), `verify_signature` accepts the request unconditionally regardless of the `X-Hub-Signature` header, and `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs on fully attacker-controlled `params`: [5](#0-4) 

The `membership` event is dispatched to `MembershipHandler`, which trusts `params.team`, `params.organization.login`, and `params.member.login` completely, creating/looking-up a `Team` and adding the named user as a member with no additional verification: [6](#0-5) 

`Team#organization` is set straight from the forged payload, and `User#authorized?` grants app access based purely on membership in a team belonging to `Shipit.github_teams`: [7](#0-6) 

### Impact Explanation
An unauthenticated attacker who crafts a `membership` webhook naming a GitHub login and any team configured in `Shipit.github_teams` (or a team ID the attacker learns/guesses) whose organization lacks a `webhook_secret` can add that GitHub login to the authorizing team's membership record without ever touching GitHub. Once the attacker (or an accomplice controlling that GitHub login) completes the normal OAuth login flow, `current_user.authorized?` succeeds and Shipit access, including the ability to deploy/rollback/merge, is granted. This matches the "High: escalation into `Shipit.github_teams` authorization" impact tier and can be chained toward the "Critical: unauthorized deploy/rollback/merge" tier once inside.

### Likelihood Explanation
Likelihood depends on operator configuration: any organization referenced in `Shipit.github_teams` (or reachable via `Team.find_or_create_by_handle`) that has not set a per-org `webhook_secret` is exploitable with a single unauthenticated POST to `/webhooks`, no credentials required. Because the docs explicitly present the webhook secret as optional, and multi-organization deployments configure secrets per-org in `github_app_config`, it is plausible for at least one configured organization to be left without a secret while `Shipit.github_teams` still references teams under it.

### Recommendation
- Make webhook signature verification fail closed: `verify_webhook_signature` should reject the request (return `false`) when `webhook_secret` is blank, instead of returning `true`.
- Resolve/authorize the target organization independent of unverified payload fields where feasible, or verify the signature using a fixed/known-good secret before trusting any payload-derived routing key.
- Optionally require `webhook_secret` to be present for any organization referenced by `Shipit.github_teams`, and warn/fail startup if missing.

### Proof of Concept
1. Configure Shipit with `Shipit.github_teams` including a team under organization `victim-org`, but do not set `webhook_secret` for `victim-org` in `secrets.github`.
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-controlled-login" }
}
```
No valid `X-Hub-Signature` is required because `repository_owner` resolves to `victim-org`, whose missing `webhook_secret` makes `verify_webhook_signature` return `true` unconditionally (`lib/shipit/github_app.rb:76-83`).
3. `MembershipHandler#process` creates/uses `Team#github_id == 999` and adds `attacker-controlled-login` as a member (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`).
4. The att attacker logs in via GitHub OAuth as `attacker-controlled-login`, and `User#authorized?` returns `true` because the membership record now exists (`app/models/shipit/user.rb:80-82`).
5. Attacker gains full Shipit access (deploy, rollback, merge).

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
