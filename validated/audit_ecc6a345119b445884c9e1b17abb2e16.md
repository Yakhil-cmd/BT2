## Analysis

This confirms the exploitable analog: `User#authorized?` in `app/models/shipit/user.rb:80-82` grants application access whenever a user is a member of any `Team` matching `Shipit.github_teams`, and `Team` membership is populated by `MembershipHandler` from unauthenticated webhook data. [1](#0-0) 

The binding that breaks is: **organization authenticated by `verify_signature` (`repository.owner.login`/`organization.login`) ≠ organization whose `Team`/membership state is mutated by the handler (`params.organization.login`, `params.team.id`)**.

`WebhooksController#verify_signature` selects which `Shipit.github(organization:)` config (and therefore which `webhook_secret`) to check against, using only `repository_owner`, itself read straight out of the unauthenticated JSON body: [2](#0-1) [3](#0-2) 

Crucially, `GithubApp#verify_webhook_signature` returns `true` unconditionally when the org's `webhook_secret` is blank: [4](#0-3) 

This is a documented, supported configuration state — the shipped sample config explicitly shows `webhook_secret: # nil` per organization: [5](#0-4) 

Once verification passes (because the attacker addressed the request to an org configured with no `webhook_secret`), the actual event body is dispatched to handlers by `Shipit::Webhooks.for_event(event)`, and `MembershipHandler` trusts the **body's own** `organization.login` and `team` fields — not the value used for signature routing — to create/update a `Team` and add/remove members: [6](#0-5) 

Since the signature check and the handler both read from the same unauthenticated JSON, and the check only proves "this body came from *an* org with a blank secret," an attacker can freely set `organization.login`/`team.id`/`team.slug` to any values, including those matching a `Team` used for `Shipit.github_teams` authorization on a completely different, security-sensitive organization/repository. `Team.find_or_create_by!(github_id: params.team.id)` will match an existing high-privilege team by its numeric GitHub team id if the attacker knows or guesses it, or create a new one that later gets legitimately populated. Adding an attacker-controlled `User.find_or_create_by_login!(params.member.login)` (also attacker-controlled, arbitrary GitHub login string) to that `Team` via `team.add_member(member)` directly satisfies `authorized?`'s `teams.where(id: Shipit.github_teams.map(&:id)).exists?` check for that user login — a real self-escalation into the app's team-based authorization if that login is later used to log in via GitHub OAuth.

### Title
Unauthenticated membership webhook can grant Shipit.github_teams authorization via an org with no configured webhook_secret - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` picks the `GithubApp` (and its `webhook_secret`) to verify against solely from the attacker-supplied `repository.owner.login`/`organization.login` field of the JSON body, and `GithubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatically verified. Any Shipit multi-org deployment that has at least one org configured without a `webhook_secret` (a supported, documented configuration) lets an unauthenticated attacker submit a forged `membership` event whose `organization`/`team`/`member` fields are unrelated to the "verified" org, causing `MembershipHandler` to create/mutate a `Team` and add an arbitrary login as a member of it.

### Finding Description
- The organization used to authenticate the webhook (`repository_owner` in `WebhooksController`) and the organization/team acted upon by `MembershipHandler` (`params.organization.login`, `params.team.id`) both come from the same unauthenticated request body, with no cross-check that they match, and no requirement that they belong to the org whose secret was used.
- If `verify_webhook_signature` short-circuits to `true` (blank `webhook_secret`), the request is accepted regardless of which org it "claims" to be for.
- `MembershipHandler.process` then blindly trusts `params.team.id`/`params.organization.login` to find-or-create a `Team`, and `params.member.login` to find-or-create a `User`, then calls `team.add_member(member)`.
- `Team#id` is only scoped by GitHub's numeric `github_id`; if that id collides with (or is chosen by an attacker who can enumerate) a `Team` referenced in `Shipit.github_teams`, `authorized?` becomes true for the attacker's chosen login.

### Impact Explanation
This breaks the "GitHub identity authenticated vs. authorization team mutated" binding and results in escalation into `Shipit.github_teams` authorization (High impact per the rules) without any GitHub credential, Shipit session, or API token — a fully unauthenticated attacker reaching the `/webhooks` endpoint is sufficient, as long as any configured org lacks a `webhook_secret`.

### Likelihood Explanation
Requires the operator to have at least one organization entry in `Shipit.github` without a `webhook_secret` — explicitly shown as a valid/blank value in the shipped `config/secrets.development.shopify.yml` sample, so it is a realistic operational configuration rather than a contrived edge case. No other precondition (no auth, no token, no repo access) is needed.

### Recommendation
- Require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`).
- Verify that `repository.owner.login`/`organization.login` used to select the signing org matches the `organization.login`/`team.organization` acted on by handlers like `MembershipHandler` before applying membership changes.
- Consider scoping `Team.find_or_create_by!` lookups by `organization` in addition to `github_id`, and validating team/organization pairs server-side via the GitHub API rather than trusting webhook body fields for authorization-relevant state.

### Proof of Concept
1. Deploy Shipit configured with two orgs: `org-a` (attacker has no privileges, but is what `verify_signature` will resolve to) with `webhook_secret` unset, and `org-b` whose GitHub team id `T` is listed in `Shipit.github_teams`.
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": T, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/teams/T" },
  "organization": { "login": "org-a" },
  "member": { "login": "attacker-controlled-login" }
}
```
3. `repository_owner` resolves to `org-a` (via `organization.login` fallback), whose blank `webhook_secret` makes `verify_webhook_signature` return `true` unconditionally.
4. `MembershipHandler` runs, calling `Team.find_or_create_by!(github_id: T)` (matching the privileged team from `org-b`) and adding `attacker-controlled-login` as a member.
5. When a GitHub user with login `attacker-controlled-login` later authenticates via OAuth, `User#authorized?` returns `true` because `teams.where(id: Shipit.github_teams.map(&:id)).exists?` is satisfied.

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L6-14)
```yaml
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
