### Title
Webhook signature verification keyed by attacker-controlled `organization`/`repository.owner` field, decoupled from the `repository.full_name` actually processed — cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/organization secret to use for HMAC verification based on a value taken directly from the untrusted, unparsed request body, and that value is not the same field the event handlers later use to resolve the target repository/stack. In a multi-tenant Shipit deployment (multiple GitHub Apps configured under `config/secrets.yml`'s `github:` section, one per organization, exactly as documented in `docs/setup.md:181-216` and exercised by the test fixture `test/dummy/config/secrets_double_github_app.yml`), this breaks the intended binding: "the organization whose secret authenticated the request" ≠ "the repository the request is allowed to act on".

### Finding Description
`WebhooksController#verify_signature` computes the authenticating organization like this: [1](#0-0) 

and: [2](#0-1) 

`repository_owner` is read straight out of the raw JSON body (`params.dig('repository','owner','login') || params.dig('organization','login')`) *before* the signature has been validated. This value is used only to pick which `GitHubApp`/`webhook_secret` (`Shipit.github(organization: repository_owner)`) is used to verify the HMAC of the *entire* payload.

Once verification passes, `create` re-parses the same untrusted body and dispatches to handlers: [3](#0-2) 

Every handler resolves the actual target repository/stack from a **different** field of the same body — `repository.full_name` — via `Handler#repository_name`/`#stacks`: [4](#0-3) 

and e.g. `PushHandler`, which drives `stack.sync_github`: [5](#0-4) 

Signature verification itself is a no-op when the resolved organization has no `webhook_secret` configured: [6](#0-5) 

The engine's own multi-org test fixture demonstrates this as a supported configuration shape (both orgs with `webhook_secret: # nil`): [7](#0-6) 

Break-down of the broken binding, evaluated before/after an attacker request:
- **Before**: intended invariant — `organization_that_authenticated == organization_owning(repository.full_name)`.
- **After**: an attacker POSTs directly to the public `/webhooks` endpoint (no session, no `ApiClient` token, no GitHub write access needed — this endpoint is designed to be called by GitHub itself and skips `verify_authenticity_token`) with `organization.login` (or `repository.owner.login`) set to *OrgA* (any org configured in Shipit whose `webhook_secret` is unset/blank/leaked) while `repository.full_name` is set to `"OrgB/target-repo"`, an org/repo that is actually tracked by Shipit under a stricter `webhook_secret`. `verify_signature` looks up and "verifies" against *OrgA*'s (permissive) app config and passes trivially, then the handler acts on *OrgB*'s tracked stack.

This is the direct analog of the reported bug class: a value used to satisfy an admission/limit/authorization check (there: `consensusRadius`/`archivers.size`; here: which org's secret gates the request) is not the same value that is subsequently acted upon (there: `joinRequests` appended unconditionally; here: `repository.full_name` processed unconditionally once *any* org's check passes) — the check and the effect are bound to different pieces of attacker-supplied data.

### Impact Explanation
Exploiting the mismatch lets an unauthenticated attacker forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`) attributed to any repository/stack tracked by the Shipit instance, as long as the instance has at least one configured organization with a missing/blank `webhook_secret` (a state the engine explicitly supports and even ships as a documented/test configuration). Concretely:
- A forged `push` event drives `PushHandler` → `stack.sync_github`, which can seed `undeployed_commits` for a stack under continuous deployment, leading to an **unauthorized deploy** of an attacker-chosen (but pre-existing, on GitHub) commit — matching the report's rubric "unauthorized deploy, rollback or merge".
- A forged `membership` event can call `MembershipHandler#process`, adding an arbitrary GitHub login to a `Team` object whose `id`/`organization` come straight from the payload — an **escalation into `Shipit.github_teams` authorization**, one of the explicitly listed High-severity outcomes, since `authorized?` gates access purely on `teams.where(id: Shipit.github_teams.map(&:id)).exists?`.

Both outcomes are explicitly enumerated acceptable impacts (unauthorized deploy; escalation into `Shipit.github_teams` authorization), and neither requires a Shipit session, `ApiClient` token, `webhook_secret`, `api_clients_secret`, GitHub App private key, repository write access, or TLS interception — only knowledge that some org configured in the instance lacks (or has a guessable/blank) `webhook_secret`, which the engine's own documentation/tests show as a valid state.

### Likelihood Explanation
Likelihood is conditioned on the operator having configured at least one organization without a `webhook_secret` (common in local/dev/staging setups, and explicitly modeled in `test/dummy/config/secrets_double_github_app.yml`) in a multi-org deployment that also tracks at least one other, better-protected organization's repositories — a realistic operational scenario for any Shipit instance serving multiple GitHub orgs, since nothing in the code enforces that all configured orgs' webhook secrets be equally strong, nor that the org used for verification match the org whose repository is mutated.

### Recommendation
- Derive the organization used for signature verification and the organization used for repository/stack resolution from the *same* single field, and require they be present/consistent before any processing (reject if `repository.owner.login` conflicts with the top-level `organization.login`, or if the resolved stack's tracked repository owner differs from `repository_owner`).
- Make `verify_webhook_signature` fail closed instead of `return true unless webhook_secret`; a GitHub App configured for webhook handling should always require a webhook secret, or the app should refuse to route hooks for that org.
- After a webhook is verified, re-check inside each handler that the resolved `Stack`/`Repository`'s owning organization equals the organization that satisfied `verify_signature`, rejecting mismatches.

### Proof of Concept
1. Configure a multi-org Shipit instance per `docs/setup.md`'s "Using Multiple Github Applications" section, with `OrgA` having `webhook_secret:` left blank and `OrgB` tracking a real stack (`OrgB/target-repo`) with `continuous_deployment: true` and a properly-set `webhook_secret`.
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "organization": { "login": "OrgA" },
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" },
  "ref": "refs/heads/master",
  "after": "<any existing commit sha on OrgB/target-repo>"
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required, since `verify_webhook_signature` short-circuits to `true` for `OrgA` (no secret configured).
3. `WebhooksController#verify_signature` resolves `repository_owner` → `"OrgA"`, loads `Shipit.github(organization: "OrgA")`, and passes verification unconditionally.
4. `PushHandler#process` resolves the stack via `repository.full_name` = `"OrgB/target-repo"` (unrelated to the org that "authenticated" the request) and calls `stack.sync_github(expected_head_sha: ...)`, triggering commit sync and, if continuous deployment is enabled, an unauthorized deploy of `OrgB`'s stack — despite the attacker never possessing `OrgB`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-23)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-79)
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
```
