### Title
Webhook signature verification can be bypassed by choosing an organization with no configured `webhook_secret`, allowing unauthenticated forgery of `membership` events that grant `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook against using an attacker-controlled field of the unauthenticated JSON body (`repository.owner.login` / `organization.login`), and `GitHubApp#verify_webhook_signature` trivially returns `true` whenever that selected organization has no `webhook_secret` configured. Because Shipit explicitly supports multiple organizations with an *optional* per-organization webhook secret, an attacker can pick any org lacking a secret to make signature verification a no-op, then have the rest of the same payload processed by handlers that trust unrelated fields of the body — including `Handlers::MembershipHandler`, which adds an arbitrary GitHub login to an arbitrary `Team`. Teams back `Shipit.github_teams`, which gates `current_user.authorized?`. This lets an unprivileged attacker escalate into the app's authorization system.

### Finding Description
`verify_signature` picks the verification target purely from body content, before any authentication has occurred: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` bypasses HMAC verification entirely if the resolved org's secret is blank: [3](#0-2) 

This is not a hypothetical misconfiguration: the setup docs mark the webhook secret as optional, and the multi-org test fixture ships an organization (`OrgTwo`) with a `nil` webhook secret, confirming this is a supported deployment shape: [4](#0-3) [5](#0-4) 

Once `verified` short-circuits to `true`, the full, still-unauthenticated `params` blob is dispatched to all handlers for the declared event: [6](#0-5) 

Handlers use *other* fields of the same body — never checked against the org used for verification — to decide what to mutate. `Handler#repository_name` reads `repository.full_name` independent of `repository.owner.login`: [7](#0-6) 

Most importantly, `MembershipHandler` trusts `organization.login`, `team.*`, and `member.login` from the payload to look up/create a `Team` and add an arbitrary user as a member: [8](#0-7) 

`Team#add_member` performs no additional GitHub-side validation: [9](#0-8) 

`Shipit.github_teams` and team membership gate access in `force_github_authentication`, which is checked for every authenticated session: [10](#0-9) 

**Binding broken:** the GitHub organization whose (absent) secret was used to authenticate the webhook request ≠ the organization/team/repository whose state the handler actually writes. The webhook signature is supposed to bind "this payload came from GitHub for org X" to "this payload's claims about org X's teams/repos are trustworthy" — but the org used for the trust check and the org/team/repo acted upon are never the same field, and the check itself is a no-op whenever any configured org lacks a secret.

### Impact Explanation
An attacker who knows (or discovers, e.g. by probing `repository_owner` values from public GitHub org names configured on the Shipit instance) any org in `Shipit.github` with no `webhook_secret` can:
1. Send a forged `membership` webhook with `organization.login` set to that unsecured org, `team` set to the `github_id`/slug of a real team present in `Shipit.github_teams` (used to restrict app access), and `member.login` set to the attacker's own GitHub username.
2. `MembershipHandler` creates/finds a `User` for that login and adds it to the authorized `Team` — with no signature actually validated.
3. The attacker then performs a normal OAuth login with their own account; `force_github_authentication` finds the same `User` row, now a member of an authorized team, and grants full authenticated access to the Shipit application.

This is an escalation into `Shipit.github_teams` authorization performed by an unprivileged, unauthenticated network attacker — explicitly listed as a High-severity impact category. The same bypass also lets an attacker forge `push`/`status` events (e.g., injecting fake commit statuses via `StatusHandler`) against stacks/repositories unrelated to the org whose missing secret was exploited.

### Likelihood Explanation
Likelihood is high in any multi-organization Shipit deployment where at least one configured GitHub App lacks a webhook secret — a configuration explicitly documented as optional and demonstrated in the project's own test fixtures. No credentials, sessions, or repository write access are required; the attacker only needs to send one crafted, unauthenticated HTTP POST to `/webhooks` and then complete an ordinary OAuth login with their own GitHub account.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub App/organization (fail closed instead of `return true unless webhook_secret`).
- Never select the verification target (which secret to check) from unauthenticated payload fields; instead verify against every configured secret (or otherwise ensure the signing key cannot be attacker-chosen).
- After signature verification succeeds, cross-check that the org used to verify equals the org referenced by the fields each handler acts on (e.g., `MembershipHandler`'s `organization.login`, `Handler#repository_name`'s owner) before mutating any state.
- For `MembershipHandler` specifically, consider re-validating team membership against the GitHub API rather than trusting webhook payload content for authorization-relevant writes.

### Proof of Concept
1. Configure (or identify) an organization `OrgWithoutSecret` in `Shipit.github` with `webhook_secret` unset — a documented, supported configuration (`docs/setup.md`, and mirrored by the `OrgTwo` test fixture).
2. Identify a `Team` already present in the Shipit DB / `Shipit.github_teams` that gates access, e.g. `shopify/developers` with `github_id = 123`.
3. Send, without any valid GitHub signature:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=0000000000000000000000000000000000000000

{
  "action": "added",
  "team": {"id": 123, "name": "Developers", "slug": "developers", "url": "http://example.com"},
  "organization": {"login": "OrgWithoutSecret"},
  "member": {"login": "attacker-github-login"},
  "repository": {"owner": {"login": "OrgWithoutSecret"}}
}
```
- `repository_owner` resolves to `OrgWithoutSecret`.
- `verify_webhook_signature` returns `true` immediately because `webhook_secret` is blank for that org — no HMAC check performed at all.
- `MembershipHandler#process` runs, creates/finds `User` `attacker-github-login`, and adds it to `Team` #123.
4. Attacker completes normal GitHub OAuth login as `attacker-github-login`. `force_github_authentication` now finds this user is a member of an authorized team and grants access, even though the attacker was never actually a member of the real GitHub team/org.

(Note: I could not directly view `app/models/shipit/user.rb`'s `authorized?` implementation within the available context, but its existence and the `Shipit.github_teams` gating in `authentication.rb` are directly confirmed; a Devin session with full file access can verify the exact `authorized?` predicate if further confirmation is desired.)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
