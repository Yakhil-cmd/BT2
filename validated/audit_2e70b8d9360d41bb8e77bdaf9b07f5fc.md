### Title
Unsigned GitHub webhook accepted when `webhook_secret` is unset, allowing forged `membership` events to grant `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when an organization's `webhook_secret` is blank, so `WebhooksController#verify_signature` never validates provenance for that org. Combined with `MembershipHandler#process`, an unauthenticated attacker can POST a fabricated `membership` event and add an arbitrary GitHub login to any locally-known `Team` record (matched only by `params.team.id`), which can grant `User#authorized?` if that team is in `Shipit.github_teams`.

### Finding Description
The broken binding is: **a webhook body must be cryptographically tied to `organization.login`** — i.e. `HMAC(webhook_secret_for(org), raw_body) == signature`. This equality is never evaluated when `webhook_secret` is blank: [1](#0-0) 

`WebhooksController#verify_signature` resolves the app purely from `repository_owner`, which falls back to `params.dig('organization', 'login')` when there is no `repository` key (true for `membership` events), then calls `verify_webhook_signature`. If it returns `true` (unset secret), no HMAC check occurs at all: [2](#0-1) 

`MembershipHandler#process` then trusts the fully attacker-controlled body: it resolves/creates a `Team` keyed only on `params.team.id` (`github_id`) and adds `params.member.login` (created via `User.find_or_create_by_login!`) as a member: [3](#0-2) 

`User#authorized?` grants access based purely on team membership matching `Shipit.github_teams` ids: [4](#0-3) 

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: membership`, no `X-Hub-Signature` (or any garbage value), and a body naming `organization.login` = an org configured in Shipit without a `webhook_secret`, `team.id` = the `github_id` of a Team already known to Shipit and referenced in `Shipit.github_teams` (e.g., previously created via the legitimate onboarding rake task), `action: "added"`, and `member.login` = the attacker's own GitHub login (or any login of their choosing, since `User.find_or_create_by_login!` will create the user record if it doesn't exist). This adds that user to the privileged team without ever proving control of the organization's webhooks.

Existing guards fail here specifically because: `drop_unhandled_event` only checks that a handler exists for the event type, not signature; `ExplicitParameters` (`MembershipHandler.params`) only validates shape, not provenance; and `verify_signature`'s only protection collapses to a no-op when `webhook_secret` is nil, which `docs/setup.md` documents as an optional/allowed configuration.

### Impact Explanation
An attacker with no Shipit credentials can write `Membership` and `User` rows for any organization configured without a `webhook_secret`, and — if that organization's team ids overlap with `Shipit.github_teams` — self-escalate into the set of users treated as `authorized?` across the whole Shipit instance. This is a cross-tenant authentication-bypass class issue (a forged webhook is accepted as authentic), matching the "escalation into `Shipit.github_teams` authorization" / "authentication bypass (forged webhook ... accepted)" impact categories. It is repeatable against every organization in the installation that lacks a configured `webhook_secret`, and against any team whose `github_id` is discoverable/guessable by the attacker.

### Likelihood Explanation
Preconditions: at least one org configured in Shipit (via GitHub App or webhook config) with `webhook_secret` left blank — explicitly documented as an allowed/optional configuration — and a `Team` record already existing locally (created e.g. through the standard onboarding flow) whose `github_id` the attacker can determine (team ids are often enumerable/guessable via GitHub's public API for the org's teams, or simply from a prior legitimate `membership` webhook, since it's not a secret). No signature, no session, no API token needed — one crafted HTTP request suffices. This is highly feasible and requires zero privileged access.

### Recommendation
Do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is blank; instead require an operator-configured secret for any organization capable of triggering privilege-bearing handlers (e.g., `membership`), or fail closed (`return false unless webhook_secret`) and surface a configuration warning. Additionally, `MembershipHandler` should not be able to affect authorization-relevant `Team` membership from an org whose webhook authenticity wasn't cryptographically verified.

### Proof of Concept
1. In test setup, configure `Shipit.github` for organization `"acme"` with `webhook_secret: nil` (mirrors an operator installing without a secret) and seed a `Team` with `github_id: 999`, `organization: "acme"`, and ensure `Shipit.github_teams` returns that team's local `id`.
2. Build a `membership` payload: `{action: "added", team: {id: 999, name: "x", slug: "x", url: "http://x"}, organization: {login: "acme"}, member: {login: "attacker"}}`.
3. `POST /webhooks` with header `X-Github-Event: membership` and no `X-Hub-Signature` header (or an invalid one).
4. Assert: response is `200 OK` (not `422`); `Shipit::Membership.exists?(user: Shipit::User.find_by(login: "attacker"), team_id: team.id)` is `true`; and `Shipit::User.find_by(login: "attacker").authorized?` is `true` — demonstrating the equality `HMAC(secret, body) == signature` was never checked and an unauthenticated write mutated the authorization-relevant `Team`/`Membership` state.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
