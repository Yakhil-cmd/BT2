### Title
Webhook signature check is skipped when an organization has no `webhook_secret`, letting an unauthenticated request forge `membership` events and escalate into `Shipit.github_teams` authorization — (File: `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config to verify a webhook against using an attacker-controlled field of the *unverified* JSON body (`repository.owner.login` / `organization.login`), then delegates to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` when that config has no `webhook_secret` set. For any organization entry configured without a `webhook_secret` (a supported configuration value, not a misuse of the engine), an unauthenticated internet client can post arbitrary webhook payloads that are accepted as if legitimately signed by GitHub. The `membership` handler then writes attacker-supplied team/member data straight into the `Team`/`Membership` tables that back `User#authorized?`, the sole gate used by `Authentication#force_github_authentication` to restrict the entire Shipit UI to members of `Shipit.github_teams`.

### Finding Description
The verification chain is: [1](#0-0) 

`repository_owner` is read straight from the still-unverified JSON body: [2](#0-1) 

That attacker-controlled value is used to pick *which* GitHub App/organization config performs the verification, and the verification itself is a no-op when that config lacks a secret: [3](#0-2) 

`webhook_secret` being absent is an explicitly supported configuration state, not a deployment error — it is exercised in the engine's own multi-org config fixture and documented as optional in the setup guide: [4](#0-3) [5](#0-4) 

Because `check_if_ping`/`drop_unhandled_event`/`verify_signature` are the only gates on `WebhooksController#create`, and `verify_signature` passes trivially for that organization, an unauthenticated POST to `/webhooks` with `X-Github-Event: membership` and a body naming that organization is processed exactly like a genuine GitHub-signed delivery: [6](#0-5) 

This handler finds-or-creates a `Team` keyed by the attacker-supplied `team.id`, finds-or-creates a `User` by the attacker-supplied `member.login`, and calls `team.add_member(member)`, persisting a `Shipit::Membership` row: [7](#0-6) 

That `Membership` table is the *entire* basis for authorization once a user is otherwise logged in via GitHub OAuth: [8](#0-7) [9](#0-8) 

**Binding broken:** *organization asserted inside the (unverified) webhook payload, used to select the verifying secret* ≠ *organization that actually authenticated the request*. When the selected organization has no secret, the equality collapses to "no verification at all," so the payload's claims about team membership are trusted unconditionally.

### Impact Explanation
An unauthenticated network attacker can add any already-known Shipit `User` login (including their own account, once it exists in Shipit's `users` table from a prior legitimate GitHub OAuth login) to a `Team` whose `github_id` matches one of the org's `Shipit.github_teams`. Since `User#authorized?` only checks DB-resident `Membership` rows and never re-verifies against GitHub at request time, this directly grants that user full authorized access to the Shipit UI (stacks, deploy triggers, task triggers, etc.), bypassing the intended GitHub-team restriction. This is an escalation into `Shipit.github_teams` authorization — explicitly listed as a High-impact category for this engine.

### Likelihood Explanation
The prerequisite is that at least one organization configured in `Shipit.github` lacks a `webhook_secret` — a state the engine's own fixtures/tests treat as normal and supported, not a misconfiguration outside the documented usage. The attacker needs only: (1) the org's/team's numeric GitHub `team.id` (obtainable via GitHub's own team-listing API for any team the attacker can see, e.g., as an ordinary member of the org), and (2) a Shipit `User` row for the account to be elevated (created automatically the first time that GitHub user completes OAuth login, which requires no special privilege). No Shipit session, API token, webhook secret, or GitHub App key is needed to perform the forged POST itself.

### Recommendation
- Do not select the verifying GitHub App config from unverified request data before verification, and never treat a missing `webhook_secret` as automatic success; instead, require a `webhook_secret` be configured before processing state-changing events like `membership`, or fail closed if it is unset for events with model-altering effects.
- Re-derive authorization from the GitHub API on each authorization check (or periodically re-sync via `bin/rake teams:fetch`) rather than trusting locally cached `Membership` rows populated purely from webhook deliveries.
- Add signature-algorithm coverage for `X-Hub-Signature-256` and reject deliveries lacking any valid signature header outright rather than falling back to "no secret ⇒ trusted."

### Proof of Concept
Given a Shipit deployment where organization `AcmeOrg` (used by stack `acme/widgets`) has `webhook_secret` unset in `secrets.yml`, and `Shipit.github_teams` includes a team with GitHub `id: 4242` (`AcmeOrg/admins`):

```
POST /webhooks HTTP/1.1
Host: shipit.acme.example
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": { "id": 4242, "name": "admins", "slug": "admins", "url": "https://api.github.com/teams/4242" },
  "organization": { "login": "AcmeOrg" },
  "member": { "login": "attacker-github-login" }
}
```

No `X-Hub-Signature` header is required to be valid because `verify_webhook_signature` returns `true` for `AcmeOrg` (no `webhook_secret`). The `MembershipHandler` creates/updates `Team#4242` and adds `attacker-github-login` as a member. After the attacker separately logs into Shipit once via GitHub OAuth (creating their `User` row), `User#authorized?` now returns `true` for that account, granting full UI access despite never having actually been a member of `AcmeOrg/admins` on GitHub.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L42-46)
```yaml
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/membership.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
  class Membership < Record
    belongs_to :team, required: true
    belongs_to :user, required: true

    validates :user_id, uniqueness: { scope: :team_id }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
