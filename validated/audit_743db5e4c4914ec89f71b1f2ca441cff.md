### Title
Unauthenticated `/webhooks` membership forgery bypasses GitHub App signature verification and grants `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The reported bug class is a broken binding between a value that was verified and a value that is actually acted on. The same class exists in `WebhooksController`: the GitHub App (and its `webhook_secret`) used to verify a webhook is selected from an **unverified** payload field, and `verify_webhook_signature` unconditionally returns `true` whenever that selected app has no `webhook_secret` configured — a state explicitly documented as "optional." This lets an unauthenticated caller submit a forged `membership` event that the `MembershipHandler` uses to add an arbitrary `User` (identified only by public GitHub login) to a `Team`, escalating that user into `Shipit.github_teams` authorization the next time they complete the normal GitHub OAuth login.

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App configuration to check the signature against using data taken directly from the untrusted JSON body, before any verification occurs: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` bypasses the HMAC check entirely if the selected app has no `webhook_secret` set: [3](#0-2) 

The setup documentation explicitly states the webhook secret is optional per GitHub App/organization: [4](#0-3) [5](#0-4) 

Once verification passes (or is bypassed), the raw, attacker-controlled JSON body is handed to registered handlers with no further authentication and no cross-check that the fields used by the handler correspond to the org/repo used to select the trust anchor: [6](#0-5) 

`MembershipHandler` trusts `organization.login`, `team`, and `member.login` straight from this payload to create/attach team membership, with no verification that this data reflects a real GitHub event: [7](#0-6) 

`Team#add_member` and the resulting membership feed directly into the authorization check used by every engine controller: [8](#0-7) 

This breaks the equality the rules call out: `organization authenticated by verify_signature` ≠ `repository/organization/team acted on by the handler`. Verification is keyed off an org name taken from the same untrusted body it is supposed to protect, and is a no-op whenever that org has no secret configured — a documented, non-privileged, non-default-hardened state.

### Impact Explanation
A successful forged `membership` event lets an outside attacker who knows only a configured GitHub organization's name (public) and a team slug listed in `Shipit.github_teams` (also typically discoverable/public) grant Shipit-side team membership to any GitHub login, including their own. When that login subsequently completes the normal "Login with GitHub" OAuth flow (open to any GitHub user by design), `current_user.authorized?` succeeds because the forged `Membership` record now satisfies the `Shipit.github_teams` check — this is escalation into `Shipit.github_teams` authorization, one of the explicitly listed High-impact outcomes. From there the attacker has full authenticated UI access to trigger deploys, rollbacks, and merges on any stack the engine manages.

### Likelihood Explanation
The only prerequisite is a Shipit deployment where at least one configured GitHub organization (in a single-app or multi-app `github:` config) has no `webhook_secret` set — explicitly presented as an optional field in the project's own setup guide, so this is a realistic, documented configuration rather than a hypothetical misconfiguration. No credentials, sessions, `ApiClient` tokens, or GitHub App secrets are required; the request is a single unauthenticated `POST /webhooks`.

### Recommendation
Do not select the verification secret from unverified payload data. Verify the raw request against every configured secret (or a single well-known secret if organizations share one) before trusting any field in the body, and reject requests when no secret can be positively matched — do not treat an absent `webhook_secret` as "verification not required." Additionally, `MembershipHandler` (and other handlers) should not create or mutate `Team`/`Membership` records purely from webhook payload contents without corroborating the change against the GitHub API using the app's own credentials.

### Proof of Concept
1. Identify a Shipit instance's configured GitHub organization name that has no `webhook_secret` set (per docs, this is an optional field many operators leave blank), and a team slug present in `Shipit.github_teams`.
2. Send, unauthenticated:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything

{
  "action": "added",
  "organization": { "login": "<configured-org-without-secret>" },
  "team": { "id": 999999, "name": "Deploy Team", "slug": "<team-in-shipit_github_teams>", "url": "https://github.com/x" },
  "member": { "login": "<attacker-github-login>" }
}
```
3. `verify_signature` selects the app for `<configured-org-without-secret>`, finds `webhook_secret` blank, and returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`), so the forged request is accepted with `head(:ok)`.
4. `MembershipHandler#process` creates/updates the `Team` and calls `team.add_member(User.find_or_create_by_login!("<attacker-github-login>"))`.
5. The attacker completes a normal GitHub OAuth login as `<attacker-github-login>`; `Authentication#force_github_authentication` finds them authorized via the forged team membership and grants full app access.

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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
