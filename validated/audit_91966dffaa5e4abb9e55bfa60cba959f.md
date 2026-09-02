### Title
Webhook Organization Selected for Signature Verification Is Decoupled From the Repository/Organization Actually Written, Allowing Cross-Organization Webhook Forgery When Any Configured Org Has No `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate an inbound webhook against using an attacker-supplied field of the *unverified* JSON body (`repository.owner.login` / `organization.login`), while the code paths that actually mutate state (`Handler#repository_name`, `MembershipHandler`) read a *different* field from that same body to decide which repository/stack/team/organization to act on. Because Shipit supports multiple GitHub organizations behind a single `/webhooks` endpoint and per-org `webhook_secret` is documented as optional, if any one configured organization has a blank secret, `verify_webhook_signature` unconditionally returns `true` for that organization — letting an attacker pick that weak org to pass verification while pointing the payload's repository/organization fields at a different, protected org's stack or team.

### Finding Description
`verify_signature` picks the org used for HMAC verification from the raw, not-yet-verified request body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` bypasses verification entirely when the selected org has no configured secret: [3](#0-2) 

Shipit explicitly supports multiple orgs each with independently configured (and documented-optional) `webhook_secret`s sharing the same `/webhooks` endpoint, as shown in the multi-org secrets fixtures/docs: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes, `create` dispatches to handlers using the *same* raw payload, but the handlers read `repository.full_name` (a field never checked against `repository_owner`) to decide which `Stack`/`Repository` to act on: [6](#0-5) [7](#0-6) 

For `membership` events, the handler reads `organization.login` and `team`/`member` fields — again independent of whatever org was used to select the verification secret — and directly mutates `Team` membership: [8](#0-7) 

Team membership is exactly the authorization boundary enforced application-wide: [9](#0-8) [10](#0-9) 

**The broken binding, stated as an equality that the code fails to enforce:**
`organization used to select the webhook_secret for HMAC verification (repository_owner from the payload)` **must equal** `organization/repository the handler subsequently writes to (repository.full_name / organization.login from the same payload)` — but nothing in `verify_signature` or in the handler pipeline checks this. The HMAC only proves the payload was accepted by *the org selected via the attacker-controlled `repository_owner` field*; it proves nothing about consistency between that field and the fields the handlers actually trust.

**Before the attack (intended state):** every accepted webhook is one where GitHub itself generated `repository.owner.login`/`organization.login` matching the actual repository being pushed to, signed with that org's real webhook secret — the two fields are always naturally consistent because GitHub, not the attacker, populates them.

**After the attack:** an attacker directly POSTs an artisanal JSON body to `/webhooks` (this is a public, unauthenticated HTTP endpoint — no GitHub involvement required) with `repository.owner.login`/`organization.login` set to an org that Shipit has configured with a blank `webhook_secret` (satisfying `verify_webhook_signature`'s early `return true unless webhook_secret`), while setting `repository.full_name` (push/status/check_suite events) or `organization.login`/`team`/`member` (membership events) to target a completely different, protected organization's stack or `Shipit.github_teams`-relevant team. `verify_signature` passes because it never checks that "the org whose secret validated the request" is the same as "the org/repo the handler will mutate."

### Impact Explanation
This directly matches the required "High" impact bucket: **escalation into `Shipit.github_teams` authorization**. Using a forged `membership` event, an authenticated Shipit `User` (who logged in once via GitHub OAuth but is not a member of any `Shipit.github_teams`-listed team, and is therefore currently blocked by `force_github_authentication`) can have `MembershipHandler` add them to a `Team` whose `github_id` matches one of `Shipit.github_teams`, immediately satisfying `User#authorized?` and unlocking full access to the Shipit UI/API (deploy triggers, stack management, task streams). It can also be used to forge `push`/`status`/`check_suite` events that trigger `GithubSyncJob` or check-run refreshes for stacks belonging to organizations unrelated to the one whose weak secret was used to pass verification — an unauthorized write into another organization's deploy pipeline state. The only precondition is that at least one org configured on the Shipit instance has an unset `webhook_secret`, which the project's own setup documentation lists as optional.

### Likelihood Explanation
Likelihood is moderate-to-high in realistic multi-org deployments: the setup docs explicitly describe `webhook_secret` as optional, and nothing in the codebase enforces that all configured organizations set one, nor warns operators that a single weak org's configuration undermines isolation for every other org sharing the same `/webhooks` endpoint. No GitHub write access, session, `ApiClient` token, or private key is required — only network access to the public webhook endpoint and knowledge (or discovery) that one configured org lacks a secret.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub organization at boot (fail fast / refuse to start rather than silently allowing unauthenticated webhooks for that org).
- Never allow `verify_webhook_signature` to return `true` when no secret is configured; instead reject the request.
- Bind identity consistently: after determining `repository_owner` and verifying the signature for that specific org, re-derive `repository_name`/`organization.login` used by handlers from the same verified org context (or explicitly assert equality) rather than trusting a second, independently-read field from the same unauthenticated JSON body.

### Proof of Concept
1. Deploy Shipit configured with two organizations, e.g. `OrgWeak` (no `webhook_secret` set) and `OrgTarget` (protected, with `Shipit.github_teams` including `OrgTarget/admins`), as supported by the multi-org config shown in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker, who already has a Shipit `User` account (via one legitimate GitHub OAuth login) but is not authorized (not a member of `OrgTarget/admins`), sends:
```
POST /webhooks HTTP/1.1
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": { "id": <id-of-OrgTarget/admins-team>, "name": "admins", "slug": "admins", "url": "https://example.com" },
  "organization": { "login": "OrgTarget" },
  "member": { "login": "attacker-shipit-login" },
  "repository": { "owner": { "login": "OrgWeak" }, "full_name": "OrgWeak/whatever" }
}
```
3. `verify_signature` calls `Shipit.github(organization: 'OrgWeak')`; because `OrgWeak` has no `webhook_secret`, `verify_webhook_signature` returns `true` immediately — no signature needed at all.
4. `MembershipHandler#process` runs using `organization.login = "OrgTarget"` and `team.id` of `OrgTarget/admins`, adding the attacker's `User` as a member of that team.
5. On the attacker's next request, `User#authorized?` now returns `true` (team membership matches `Shipit.github_teams`), bypassing `force_github_authentication`'s authorization check and granting full access to Shipit for `OrgTarget`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
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
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** docs/setup.md (L28-30)
```markdown
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
