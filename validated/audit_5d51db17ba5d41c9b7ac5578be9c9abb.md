### Title
Membership webhooks are trusted per-organization but signature verification silently degrades to "always valid" for any organization configured without a `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate a webhook against based on an attacker-controlled field taken from the *unverified* request body (`repository.owner.login` / `organization.login`), then calls `GitHubApp#verify_webhook_signature`, which explicitly treats a missing `webhook_secret` as automatically valid: `return true unless webhook_secret`. Since Shipit explicitly supports "Using Multiple GitHub Applications" where each organization can independently configure (or omit) a `webhook_secret`, any deployment with at least one configured organization lacking a `webhook_secret` allows a completely unauthenticated, unprivileged attacker to submit arbitrary `membership` (or other) webhook events "as" that organization, with no GitHub credential of any kind.

### Finding Description
`repository_owner` is computed directly from the JSON body before any signature check occurs: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . This value is used to pick the `GitHubApp` instance via `Shipit.github(organization: repository_owner)` [2](#0-1) .

`GitHubApp#verify_webhook_signature` is defined to bypass verification entirely when no secret is configured for that app: `return true unless webhook_secret` [3](#0-2) . The `webhook_secret` for each organization comes straight from that organization's config block, and the setup docs explicitly mark it optional ("Webhook secret (optional)") and multiple example/test configs ship with `webhook_secret: # nil` for one or more configured organizations [4](#0-3) , and the multi-org documentation shows the same per-org independence [5](#0-4) .

The binding that is broken: **the organization whose secret authenticates the request** must equal **the organization whose team/repository state the payload writes**. Before the fix, that binding holds only accidentally — the org used for verification is read straight out of the untrusted body, and if that specific org's `webhook_secret` is blank, verification always returns `true` regardless of the `X-Hub-Signature` header, so effectively there is no authentication boundary at all for events claiming that org.

This directly weaponizes the `membership` event handler: `MembershipHandler#process` calls `Team.find_or_create_by!(github_id: params.team.id)` and `team.add_member(User.find_or_create_by_login!(params.member.login))` using entirely attacker-supplied `team.id`, `organization.login`, and `member.login` fields [6](#0-5) . Team membership is exactly what gates authorization in the app: `User#authorized?` is `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) , and `force_github_authentication` uses this exact check to gate the entire application [8](#0-7) .

### Impact Explanation
On any multi-organization Shipit deployment where at least one configured organization omits `webhook_secret` (explicitly supported/documented as optional), an unauthenticated attacker with no session, no `ApiClient` token, and no GitHub credential can:
- Send a forged `membership` webhook naming that unsecured organization, creating an arbitrary `Team` record and adding an arbitrary GitHub login (which may be an account the attacker controls) as a member.
- If that team happens to match (or is later configured to match) an entry in `Shipit.github_teams`, this escalates the attacker's account into the authorization set gating the entire Shipit UI/API — satisfying `User#authorized?` and bypassing the intended team-based access control.
- More generally, any other webhook event (`push`, `status`, `check_suite`, `pull_request`) can also be forged for that same unsecured organization, allowing unauthenticated triggering of `GithubSyncJob`, commit status writes, or PR-driven merge-queue actions.

This matches the "escalation into `Shipit.github_teams` authorization" and "unauthorized... deploy" impact categories, achieved with zero attacker credentials — a stronger and more directly exploitable analog of the original report's "signed field never matches what's actually acted upon" class of bug (there, latency config vs. feed heartbeat; here, the org used for signature selection vs. the optional/missing secret for that org).

### Likelihood Explanation
Likelihood is high specifically for deployments using the documented multi-org configuration where the operator leaves `webhook_secret` blank for one organization (shown as valid/example configuration in the repo's own docs and test fixtures). The exploit requires no privileged access, no timing dependency, and only requires the attacker to know one org name from Shipit's own configuration/UI and craft a JSON payload with `organization.login` set to that org.

### Recommendation
Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank; either require a non-blank `webhook_secret` for every configured organization, or fail closed (reject the webhook) when none is present. Additionally, avoid trusting attacker-supplied `repository.owner.login` / `organization.login` to select the verification secret before the signature is checked — the resolution of "which org's secret applies" should not itself depend on unauthenticated data whose trust is exactly what's being established.

### Proof of Concept
1. Deploy Shipit with a multi-org config (per `docs/setup.md`, "Using Multiple Github Applications") where `OrgA` has a real `webhook_secret` but `OrgB` has `webhook_secret: nil` (a documented, supported configuration, as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "Shopify/developers", "slug": "developers", "url": "https://example.com"},
  "organization": {"login": "OrgB"},
  "member": {"login": "attacker-github-login"}
}
```
Set any arbitrary/garbage value for `X-Hub-Signature` (or omit it).
3. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the header — the request passes.
4. `MembershipHandler#process` creates/updates a `Team` and adds `attacker-github-login` as a member, with no GitHub-side verification that this event ever originated from GitHub.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
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
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** docs/setup.md (L182-209)
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
