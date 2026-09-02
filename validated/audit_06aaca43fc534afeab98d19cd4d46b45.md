### Title
Webhook signature verification is keyed off an unauthenticated payload field, allowing forged webhooks for any organization whose GitHub App has no `webhook_secret` configured - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/secret to validate a webhook against using `repository_owner`, a value read directly out of the *unauthenticated* JSON body, before the signature has been checked. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that organization. Because Shipit explicitly supports (and documents) multi-organization configurations where each org can independently have `webhook_secret: nil`, an attacker can craft a raw HTTP POST claiming to be from an organization with no configured secret while embedding a `repository.full_name` that points at a *different* stack/repository that does not otherwise require any additional identity check inside the handler.

### Finding Description
The binding that should hold is: `organization used to select/verify the webhook signature == organization that authorizes the webhook's operations on the target repository`. This binding is broken:

- `repository_owner` (used to pick which `GitHubApp` config, and therefore which secret, to verify against) is extracted directly from the untrusted request body: [1](#0-0) 

- Verification is then performed using that attacker-controlled organization's secret: [2](#0-1) 

- If that organization's `webhook_secret` is blank/unset, verification is bypassed entirely regardless of the actual `X-Hub-Signature` header value: [3](#0-2) 

- `webhook_secret: nil` is a first-class, documented configuration state, not a misconfiguration — the setup docs and the multi-org fixture both show it as an acceptable/example value: [4](#0-3) [5](#0-4) 

- After the (bypassable) signature check, the controller dispatches the entire unauthenticated payload to handlers: [6](#0-5) 

- Handlers such as `PushHandler` and the base `Handler` resolve the target `Stack`/`Repository` purely from `payload.dig('repository', 'full_name')` — a field that is completely independent from, and never cross-checked against, `repository_owner` used for signature selection: [7](#0-6) [8](#0-7) 

Consequently, an attacker who knows (or controls) any single organization slug configured in `Shipit.secrets.github` with `webhook_secret` unset can send `repository.owner.login = <that org>` (satisfying the org lookup and signature bypass) while setting `repository.full_name = <victim-org>/<victim-repo>` and `ref`/`after` to arbitrary values, causing `PushHandler` to invoke `stack.sync_github(expected_head_sha: ...)` for a repository/stack that has nothing to do with the organization whose (absent) secret was used to "verify" the request.

### Impact Explanation
This breaks the "GitHub-authenticated event vs. Stack acted upon" binding described in the rules — the organization whose credential is checked (or not checked) is not the organization whose repository/stack is mutated. The practical effect is an unauthorized, unauthenticated trigger of GitHub-sync/deploy-adjacent actions (`sync_github`, commit status creation, membership/team mutation) against arbitrary stacks in the Shipit instance, without possessing any GitHub webhook secret, `ApiClient` token, or GitHub credentials for the targeted repository. This matches the High-impact class of "unauthenticated read/mutation of stack state" via a credential-binding failure, and can be escalated into forcing out-of-band syncs against victim stacks that are not the organization being impersonated.

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it requires that at least one configured organization in a multi-org (or even single-org) `Shipit.secrets.github` has `webhook_secret` unset. This is not a hypothetical edge case — it is the default/example value shown in the shipped configuration templates and fixtures, meaning operators following the documented setup without explicitly setting a webhook secret are exposed by default. No privileged session, API token, or GitHub write access is required — only a raw HTTP request to the public `/webhooks` endpoint.

### Recommendation
Do not use payload-supplied fields to select the verification key before the signature is validated. Options:
1. Require organizations to configure the endpoint per-org (e.g., separate webhook URLs per organization) so the intended organization is derived from routing, not payload content, and reject if that organization's `webhook_secret` is blank rather than treating blank as "verified."
2. After determining the org from the (still-untrusted) payload and verifying the signature, additionally verify that `payload.dig('repository', 'full_name')` belongs to that same organization before dispatching to handlers.
3. Make `webhook_secret` mandatory for every configured organization, refusing to boot/serve webhooks for orgs missing a secret, closing the unconditional-`true` bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
1. Deploy Shipit with a multi-org config where `OrgAttacker` has `webhook_secret: nil` and `OrgVictim` (hosting `OrgVictim/app`) has a real secret (mirrors `test/dummy/config/secrets_double_github_app.yml`).
2. POST to `/webhooks` with:
   - Header `X-Github-Event: push`
   - Body: `{"repository": {"owner": {"login": "OrgAttacker"}, "full_name": "OrgVictim/app"}, "ref": "refs/heads/master", "after": "<arbitrary sha>"}`
   - No valid `X-Hub-Signature` header needed.
3. `repository_owner` resolves to `OrgAttacker`; `Shipit.github(organization: "OrgAttacker")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`), and the request passes `before_action`.
4. `PushHandler.call(params)` resolves the stack via `full_name = "OrgVictim/app"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: "<arbitrary sha>")` on the victim's stack, entirely unauthenticated with respect to `OrgVictim`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
