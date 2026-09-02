### Title
`membership` webhook privilege escalation into `Shipit.github_teams` — Team lookup by `github_id` ignores the organization that was actually authenticated ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
The webhook signature check authenticates a request against the GitHub App configured for the `organization`/`repository.owner.login` field found in the *same, attacker-supplied* JSON payload, while the `membership` event handler that actually mutates authorization state (`Team` membership) resolves the target `Team` purely by the numeric `team.id` (GitHub's `github_id`), never re-checking that the authenticated organization matches the team's bound organization. This decouples "which organization's secret validated this request" from "which team's authorization record gets written," letting a request that is only valid for one (low-value/unsecured) organization silently graft membership onto a `Team` that belongs to a different, privileged organization used for `Shipit.github_teams` gating.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the HMAC secret) to validate the request against using data taken from the untrusted body itself: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` additionally short-circuits to `true` whenever that organization's `webhook_secret` is blank, which `docs/setup.md` explicitly documents as *optional*: [3](#0-2) [4](#0-3) 

Once the signature step passes, `Shipit::Webhooks::Handlers::MembershipHandler#process` resolves the `Team` to mutate strictly by `github_id`, and only stamps `team.organization` the very first time the record is created — on every subsequent event for the same `github_id` the organization field, and any relation between it and the authenticated organization, is never checked: [5](#0-4) 

`Team#authorized?`/`User#authorized?` gates admission to the whole application based on membership in `Shipit.github_teams`, whose handles (`org/slug`) are even echoed back to any unauthenticated logged-in GitHub user in the 403 message: [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization used to select/validate the webhook signature == organization that owns the Team record being mutated`

but the code only enforces:
`team.github_id (from payload) == Team.github_id (in DB)`

with no cross-check against the authenticated organization. Before the attacker's request: the victim `Team` (github_id = T) is correctly bound to the privileged organization `OrgA` (the one gating `Shipit.github_teams`). After the attacker's request, signed/validated only for a second, unrelated, low-security organization `OrgB` (present in a multi-org Shipit deployment, or simply an org whose `webhook_secret` was left unset per the documented "optional" setting), the same `Team` record (github_id = T) gains a new `Membership` for an arbitrary GitHub login the attacker controls — with the organization-authentication binding never crossed.

### Impact Explanation
This is a direct escalation into `Shipit.github_teams` authorization (an explicitly listed High-impact category): an attacker who has no Shipit session, no `ApiClient` token, and does not need `OrgA`'s webhook secret at all can add an arbitrary GitHub account (their own) as a "member" of the exact `Team` object that `Shipit.authentication.rb` checks to grant application access. All they need is:
1. Any organization known to Shipit whose `webhook_secret` is unset (a documented, supported, "optional" configuration — relevant in multi-org deployments where different orgs can have different, independently-configured `github.<org>.webhook_secret` values) or one they otherwise control the secret for.
2. The numeric `github_id` of the privileged Team (discoverable via GitHub's public teams API for many org configurations, or via the disclosed `org/slug` handle plus enumeration).

Once the forged `membership` event is accepted, the attacker's `User.find_or_create_by_login!` account is added to the privileged `Team`, satisfying `User#authorized?` and unlocking full access to Shipit (viewing deploy output, triggering deploys/tasks depending on further role checks, etc.).

### Likelihood Explanation
Likelihood is high in any deployment that runs Shipit against more than one GitHub organization (a documented, supported configuration shown in `test/dummy/config/secrets_double_github_app.yml`) where at least one configured organization has no `webhook_secret` set, or where an attacker otherwise has send access to one organization's webhook (e.g., they administer a lower-trust org that is also integrated with the same Shipit instance). No privileged credential toward the target organization is required — only toward the low-value organization used purely to pass the signature gate. The needed inputs (team numeric id, member login) are attacker-chosen or publicly discoverable, and the vulnerable code path (`MembershipHandler#find_or_create_team!`) is exercised on every `membership` webhook without exception.

### Recommendation
In `MembershipHandler#find_or_create_team!`, look up (and validate) the `Team` using both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and reject/raise if an existing team with that `github_id` has a different `organization` than the one that authenticated the current webhook. More generally, `WebhooksController#verify_signature` should tie the organization used for the signature check to the actual entity being modified by each handler, not just to attacker-controlled JSON fields, and `GitHubApp#verify_webhook_signature` should not silently accept unsigned payloads (`return true unless webhook_secret`) for any configured organization.

### Proof of Concept
1. Shipit is configured with two GitHub Apps: `OrgA` (privileged org, `Shipit.github_teams` includes `OrgA/admins`, `github_id` = 100) and `OrgB` (attacker-accessible org, `webhook_secret` unset or known to the attacker).
2. Attacker discovers `OrgA/admins`'s numeric team id (100) via GitHub's public/team API or reconnaissance.
3. Attacker sends:
   ```
   POST /webhooks
   X-Github-Event: membership
   {
     "action": "added",
     "team": { "id": 100, "name": "Admins", "slug": "admins", "url": "..." },
     "organization": { "login": "OrgB" },
     "member": { "login": "attacker-handle" }
   }
   ```
   `repository_owner` resolves to `"OrgB"`; `verify_webhook_signature` succeeds trivially (no `webhook_secret` for `OrgB`, or attacker knows it).
4. `MembershipHandler#find_or_create_team!` finds the existing `Team` with `github_id: 100` (bound in the DB to `OrgA`) — it does not re-validate `organization`.
5. `team.add_member(User.find_or_create_by_login!('attacker-handle'))` runs, creating a `Membership` for the attacker in the `OrgA/admins` team.
6. Attacker completes GitHub OAuth login on Shipit; `User#authorized?` now returns `true` because of the injected `Membership`, bypassing the intended `Shipit.github_teams` restriction entirely without ever proving membership in `OrgA`.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
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
