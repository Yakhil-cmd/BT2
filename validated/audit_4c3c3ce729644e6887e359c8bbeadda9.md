### Title
Signature verification keys off `repository.owner.login` while event handlers act on `repository.full_name`, allowing cross-organization/cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a delivery against using `repository_owner`, derived from `params.dig('repository','owner','login')` (or `organization.login`) taken from the **unverified** JSON body. But the handlers that actually mutate state (`PushHandler`, `Handler#stacks`, `PullRequest::OpenedHandler`, etc.) resolve the target `Repository`/`Stack` using a *different* field from the same unverified body: `payload.dig('repository','full_name')`. Nothing enforces that `full_name` is consistent with `owner.login` — they are independent, attacker-controlled JSON fields in a single request. This breaks the intended binding: `organization authenticated == repository written`.

### Finding Description
`verify_signature` in [1](#0-0)  picks the `GitHubApp` (and thus the `webhook_secret`) to validate the HMAC signature against based on `repository_owner`: [2](#0-1) 

Meanwhile, `Handler#stacks`/`#repository_name`, used by every concrete handler (`PushHandler`, `StatusHandler`, `PullRequest::OpenedHandler`, etc.) to find the `Repository`/`Stack` to act on, reads a separate field, `repository.full_name`: [3](#0-2) 

`GitHubApp#verify_webhook_signature` only enforces HMAC verification when a `webhook_secret` is actually configured for that resolved organization; if it is blank, verification is skipped entirely and the request is accepted: [4](#0-3) 

Because Shipit supports multiple GitHub organizations/apps configured side by side (each potentially with its own, independently-set `webhook_secret`, as shown by the multi-org secrets fixture), an attacker who can produce a validly-signed (or unsigned, if that org has no `webhook_secret`) payload for **any one** configured organization can set `repository.owner.login` (or `organization.login`) to that org while setting `repository.full_name` to point at a repository/stack belonging to a **completely different organization**: [5](#0-4) 

Example: `PushHandler#process` will run `stack.sync_github` on whichever stacks correspond to `repository.full_name`, entirely independent of the org whose secret validated the signature: [6](#0-5) 

The equality this is supposed to preserve is:
`organization whose webhook_secret authenticated the request == organization that owns the repository/stack being written to`

but nothing in `verify_signature` or `Handler` ties these two lookups (`repository_owner` vs `repository_name`/`full_name`) together — they are read from two independent, attacker-supplied JSON paths in the same unauthenticated body.

### Impact Explanation
An attacker who controls (or is a legitimate collaborator/bot on) one organization/repository configured in the Shipit instance — and can trigger or replay a validly signed webhook for that org (or target an org configured with a blank `webhook_secret`, which is explicitly supported per the secrets templates showing `webhook_secret: # nil`) — can forge push, status, check_suite, pull_request, or membership events that are processed as if they came from a *different, unrelated repository/stack* in the same multi-tenant Shipit install. This can queue `GithubSyncJob`s, write fabricated commit `Status`es used for merge/CI gating, trigger `RefreshCheckRunsJob`, unarchive review stacks, or add/remove team memberships (`MembershipHandler`) for a target the attacker does not control — a cross-repository write across an organizational trust boundary, achieved without ever holding write access, a Shipit session, or credentials to the victim repository/organization.

### Likelihood Explanation
This requires the instance to host multiple organizations/repositories (a documented, supported configuration — see `secrets_double_github_app.yml`) and requires the attacker to control delivery of a webhook for at least one configured org (their own GitHub org/repo, or any org configured without a `webhook_secret`). Given webhook payload fields are fully attacker-controlled JSON, and GitHub webhook URLs/paths are not repo-specific in this controller (a single shared endpoint dispatches by event type only, not by target), likelihood is moderate-to-high in any multi-org deployment.

### Recommendation
Bind signature verification and target resolution to the same value: derive `repository_owner` used for `Shipit.github(organization:)` from the resolved `Repository`/`Stack` record (or the same field, `full_name`), not a separate, independently-controllable field. After identifying the target `Repository` via `full_name`, re-derive `repository_owner` from that same string (or from the persisted `Repository#owner`) rather than trusting `repository.owner.login`/`organization.login` as an independent signal. Additionally, reject events whose `repository.full_name` owner segment doesn't match the org used to validate the signature.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md` / `secrets_double_github_app.yml`) with two orgs, `OrgOne` and `OrgTwo`, each with its own `webhook_secret`.
2. Attacker controls/administers a webhook delivery mechanism for `OrgOne` (e.g., because they own a repo there, or `OrgOne`'s `webhook_secret` is unset).
3. Attacker sends `POST /webhooks` with header `X-Github-Event: push`, `X-Hub-Signature` computed with `OrgOne`'s secret (or omitted if blank), and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/victim-repo"
  }
}
```
4. `verify_signature` resolves `repository_owner = "OrgOne"`, validates successfully against `OrgOne`'s (attacker-controlled/known) secret.
5. `PushHandler#stacks` resolves via `Repository.from_github_repo_name("OrgTwo/victim-repo")`, and `PushHandler#process` enqueues `GithubSyncJob` for `OrgTwo`'s stack, causing it to sync/deploy against an attacker-chosen `after` SHA — a write into `OrgTwo`'s stack triggered under `OrgOne`'s authentication.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
