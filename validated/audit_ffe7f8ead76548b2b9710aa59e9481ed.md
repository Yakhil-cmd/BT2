## Title
Webhook signature verification is keyed to an attacker-controlled organization field that is decoupled from the organization/team the handler actually acts on, allowing forged `membership` (and other) webhooks to escalate into `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The reported oracle bug mixes values that were never supposed to be combined because two computations were bound to different units. The same "wrong equality" pattern exists in Shipit's webhook pipeline: the field used to *authenticate* an inbound webhook (which GitHub App/secret to check the signature against) is not the same field the handlers use to *act*. Both fields come from the same unauthenticated JSON body, so an attacker can pick a secret-less/attacker-friendly organization for the authentication step while pointing the handler at a completely different, properly-secured organization's team/repository data.

### Finding Description
`WebhooksController#verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to validate the `X-Hub-Signature` against using `repository_owner`, itself derived purely from the unauthenticated request body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the selected organization has no `webhook_secret` configured: [3](#0-2) 

`webhook_secret` is documented and shipped as optional/nil in multi-org configurations: [4](#0-3) [5](#0-4) 

Once this trivially-satisfied check passes, `create` dispatches the *entire same payload* to event handlers, which read completely different fields to decide what to act on. The base `Handler` resolves the target repository from `payload.dig('repository', 'full_name')`, never cross-checked against `repository_owner`: [6](#0-5) 

`MembershipHandler` is even more direct: it trusts `params.organization.login`, `params.team`, and `params.member.login` from the payload to create/find a `Team` and add a `member` to it, again with no relation to whatever organization was used to select the signature secret: [7](#0-6) 

Team membership is exactly what gates access to the whole application: `User#authorized?` checks whether the user belongs to a team in `Shipit.github_teams`: [8](#0-7) 

and unauthorized users are rejected at the front door by `Authentication#force_github_authentication`: [9](#0-8) 

**Broken equality:** the engine implicitly assumes
`organization used to select webhook_secret for HMAC verification == organization/team/repository the handler subsequently writes to`.
Because both sides are read from independent, attacker-supplied JSON fields in the same unauthenticated POST body, this equality does not hold. An attacker can satisfy the left side cheaply (pick any configured organization whose `webhook_secret` is blank — a documented, supported configuration) while making the right side point at a `team`/`organization` belonging to a *different*, secured organization that is actually referenced by `Shipit.github_teams`.

### Impact Explanation
By crafting a single unauthenticated POST to `/webhooks` with `X-Github-Event: membership`, `repository.owner.login`/`organization.login` set to an org with no `webhook_secret`, but `team` set to the `github_id`/details of a real team included in `Shipit.github_teams`, and `member.login` set to the attacker's own GitHub login, the attacker causes `MembershipHandler#process` to create a `Membership` linking their `User` record to that authorized `Team`. On their next OAuth login, `authorized?` returns `true`, granting them full access to Shipit (viewing stacks, triggering deploys/rollbacks, custom tasks) without ever being a real member of that GitHub team or organization. This directly matches the specified High-impact category "escalation into `Shipit.github_teams` authorization," achieved with no valid webhook secret, no repository write access, and no privileged account.

### Likelihood Explanation
Exploitability only requires: (1) knowledge that the Shipit instance is configured with multiple GitHub organizations where at least one has no `webhook_secret` (an explicitly supported, documented configuration, and the common state before an operator bothers to set it), and (2) knowledge of a `Shipit.github_teams` entry's GitHub team id/slug/name for the target org (discoverable via GitHub's own public/team APIs or leaked config). No authentication, token, or session is needed to hit `/webhooks`; the whole point of the endpoint is to be reachable pre-auth.

### Recommendation
Verify the webhook signature using the secret configured for the organization that the payload's `repository.full_name` / event-specific target actually belongs to, and refuse to process the request if that organization cannot be unambiguously and consistently determined from a single trusted field. Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank for any organization that also appears as a source of authorization data (teams referenced by `Shipit.github_teams`); require a webhook secret whenever `Shipit.github_teams` is configured, and bind every downstream handler's organization/repository lookups to the exact organization key used during signature verification instead of re-reading independent payload fields.

### Proof of Concept
1. Configure Shipit with two organizations per `test/dummy/config/secrets_double_github_app.yml`: `OrgOne` (has `webhook_secret` set) and `OrgTwo` (no `webhook_secret`), and set `Shipit.github_teams` to include a team belonging to `OrgOne`, e.g. `OrgOne/some-team`.
2. Send an unauthenticated request:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything

{
  "action": "added",
  "team": { "id": <OrgOne_team_github_id>, "name": "some-team", "slug": "some-team", "url": "https://github.com" },
  "organization": { "login": "OrgTwo" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgTwo/whatever" }
}
```
3. `verify_signature` resolves `repository_owner` = `"OrgTwo"` (`app/controllers/shipit/webhooks_controller.rb:59-62`), fetches `OrgTwo`'s `GitHubApp`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the bogus `X-Hub-Signature`.
4. `MembershipHandler#process` runs with the full payload, creates/finds the `Team` matching `params.team.id` (the real `OrgOne` team id) and adds `member` (`attacker-github-login`) to it (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`).
5. Attacker logs in via GitHub OAuth as `attacker-github-login`; `User#authorized?` finds their new `Membership` in the `OrgOne/some-team` team listed in `Shipit.github_teams` and grants access.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-9)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
