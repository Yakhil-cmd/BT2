This is exactly the trust binding the rules describe: the webhook signature is verified against the organization derived from `params.dig('repository', 'owner', 'login')` (or the `organization` fallback), while the repository that is actually written to (looked up via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`) is taken from a *different, unverified* field of the same JSON body.

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` but the repository actually mutated is selected from the unverified `repository.full_name` field, allowing cross-repository/cross-organization writes - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` computes the GitHub App / HMAC secret to use from `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` with a fallback to `params.dig('organization', 'login')` [1](#0-0) , and then verifies `X-Hub-Signature` using that organization's `webhook_secret` [2](#0-1) . Once verified, every downstream handler (`Handler#stacks`, and each `PullRequest::*Handler#repository`) resolves the target `Repository`/`Stack` from a *separate* field of the same payload, `repository.full_name` [3](#0-2) [4](#0-3) . Nothing ties `repository.full_name` to `repository.owner.login`/`organization.login` — the HMAC only proves the payload came from *an* organization that Shipit has configured (in multi-org deployments, `Shipit.github(organization: repository_owner)` picks a per-org secret) [5](#0-4) , not that the signing organization owns the repository named in `repository.full_name`.

### Finding Description
The trust binding that should hold is: `organization that signed/authenticated the webhook == organization owning the repository that Shipit acts on`. In this multi-org configuration (`test/dummy/config/secrets_double_github_app.yml` shows `github: OrgOne: ... OrgTwo: ...`, each with its own `webhook_secret`) [6](#0-5) , `Shipit.github(organization: repository_owner)` looks up the app/secret keyed by the owner string taken from the payload itself [1](#0-0) . An attacker who is a legitimate, unprivileged installer/webhook sender for `OrgTwo` (owning some repo under their control) can send a webhook whose `repository.owner.login` (or `organization.login`) is `OrgTwo` — so it is HMAC-signed correctly with `OrgTwo`'s `webhook_secret` — but whose `repository.full_name` is set to `OrgOne/victim-repo`. `verify_signature` succeeds because the signature is valid for `OrgTwo`'s secret and the raw body [2](#0-1) . The handler then resolves the acted-upon repository purely from `repository.full_name`, i.e. `Repository.from_github_repo_name('OrgOne/victim-repo')` [7](#0-6) [3](#0-2) , so state changes (archiving review stacks, closing/merging PR bookkeeping, syncing commits, etc.) are applied to `OrgOne`'s stack/repository despite the cryptographic proof only covering `OrgTwo`.

### Impact Explanation
This breaks the equality `organization authenticated == repository written`, letting an attacker who legitimately controls webhook delivery for one configured organization mutate Shipit-side state (review stack archiving, PR/commit records, sync jobs) for a repository belonging to a different organization/stack that they do not control — a cross-repository write achieved purely by crafting the JSON body, satisfying the "cross-repository writes" Critical impact criterion, without needing an `ApiClient` token, GitHub App key, or repository write access to the victim repo.

### Likelihood Explanation
Requires only single-org attacker capability: control of one legitimate GitHub App installation/webhook delivery path already trusted by the deployment (a normal, unprivileged position for any organization onboarded to a shared Shipit instance), plus the ability to construct an arbitrary JSON payload with mismatched `repository.owner.login` and `repository.full_name` fields — no additional secrets or elevated access are needed, so likelihood is high in any multi-organization Shipit deployment.

### Recommendation
After signature verification, derive the acted-upon repository owner from the *same* verified field used for signature selection (`repository.owner.login` / `organization.login`), and reject or ignore payloads where `repository.full_name`'s owner segment does not match `repository_owner`. Alternatively, verify webhook signatures using a single global secret per Shipit instance (not fully mitigating) or cross-check the owner substring of `full_name` against `repository_owner` in `WebhooksController#verify_signature` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own `github.webhook_secret`, as in `test/dummy/config/secrets_double_github_app.yml`.
2. As an attacker who legitimately controls delivery for `OrgTwo` (e.g. an installed GitHub App/webhook endpoint under `OrgTwo`), craft a `pull_request` (or `push`) webhook body where:
   - `repository.owner.login` = `"OrgTwo"` (used only for signature-secret selection)
   - `repository.full_name` = `"OrgOne/victim-repo"` (used by the handler to select the actual `Repository`/`Stack`)
3. Sign the raw body with `OrgTwo`'s `webhook_secret` and send it to `POST /webhooks` with `X-Hub-Signature` and `X-Github-Event: pull_request`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'OrgTwo')` and validates successfully [2](#0-1) .
5. `Shipit::Webhooks.for_event('pull_request')` handlers run and resolve `repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` = `OrgOne/victim-repo` [4](#0-3) , causing `review_stack.archive!` (or equivalent state mutation) on `OrgOne`'s stack despite the request never being signed by `OrgOne`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
