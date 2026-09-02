## Title
Webhook signature verified against one organization while the handler writes state to a repository named by a different, unchecked payload field — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC against using `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) , then `repository_owner` reads that same field [2](#0-1) . However, the handlers that actually mutate state resolve the target repository/commit from a *different, independently attacker-controlled* JSON field: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` [3](#0-2) , and `StatusHandler#process` doesn't even scope by repository — it looks up `Commit.where(sha: params.sha)` across the entire installation [4](#0-3) . Nothing cross-checks that `repository.owner.login` (the identity that authenticated the request) actually matches `repository.full_name` (the identity that gets written to).

### Finding Description
Shipit is explicitly multi-tenant: `config/secrets.yml` can define multiple independent GitHub orgs, each with its own `webhook_secret`, `app_id`, and `private_key` (see `test/dummy/config/secrets_double_github_app.yml`, which configures `OrgOne` and `OrgTwo` side by side) [5](#0-4) . Each org owner independently controls their own GitHub App/webhook configuration and therefore legitimately knows their own `webhook_secret`.

The binding the engine relies on is:
`organization that authenticated (repository.owner.login)` == `repository that gets written (repository.full_name)`

This equality is never enforced. `verify_signature` picks the HMAC key via `repository_owner` [1](#0-0) , but the actual write path (`Handler#stacks` → `Repository.from_github_repo_name(repository_name)` → `Repository.from_github_repo_name`) uses `repository.full_name` from the same JSON body [3](#0-2) [6](#0-5) . Because the HMAC covers the raw bytes of the whole payload but not any *semantic* constraint tying these two fields together, an attacker who administers OrgA (and thus legitimately knows OrgA's `webhook_secret`) can craft a signed payload where:
* `repository.owner.login = "OrgA"` (passes `verify_signature`, since it's signed with OrgA's real secret)
* `repository.full_name = "OrgB/victim-repo"` (used by the handler to locate the `Repository`/`Stack`/`Commit` to mutate)

`StatusHandler` is the most severe instance: it does not consult `repository.full_name` or any repository scoping at all — it matches purely on `sha` across every `Commit` in the Shipit instance [4](#0-3) , then calls `commit.create_status_from_github!(params)`, letting the attacker (authenticated only as OrgA) set an arbitrary CI status/state on any commit belonging to any other tenant's stack.

### Impact Explanation
This breaks the "organization authenticated vs. repository written" binding called out as a valid analog class. A tenant that only controls their own GitHub App/webhook secret can:
* Force `sync_github`/push processing against another tenant's `Stack` (`PushHandler#process` iterates `stacks.not_archived.where(branch:)` from the forged `repository.full_name`) [7](#0-6) .
* Forge a passing CI `status` for a commit belonging to a completely unrelated stack/organization via `StatusHandler`, which can flip `Commit#deployable?`/safety checks used to gate deploys, i.e., manufacture the conditions for an unauthorized deploy on infrastructure the attacker does not own [4](#0-3) .

This satisfies the "unauthorized deploy" / cross-repository write class of impact required by the rules.

### Likelihood Explanation
Any tenant configured in a multi-org Shipit deployment (a normal, documented configuration — see `test/dummy/config/secrets_double_github_app.yml`) can mount this without any additional privilege: they only need their own legitimately-provisioned webhook secret, a single POST to `/github/webhooks` with `X-Github-Event: status` (or `push`), and knowledge of a target commit `sha` (visible on public GitHub repos or via the deployed app's own commit lists). No victim secret, private key, or session token is required.

### Recommendation
Enforce the equality explicitly: after computing `repository_owner` for signature verification, re-derive/validate that `repository.full_name`'s owner segment (and, for `StatusHandler`, the resolved `Commit`'s `Stack`/`Repository` owner) matches `repository_owner`/the authenticated GitHub App installation before any handler is allowed to mutate state. Reject (422) whenever these disagree, and scope `StatusHandler`'s `Commit` lookup by the authenticated repository rather than by `sha` alone.

### Proof of Concept
1. Tenant admin for `OrgA` (legitimately configured in `secrets.yml` with `webhook_secret: SECRET_A`) knows `SECRET_A`.
2. Craft a `status` webhook payload:
```json
{
  "sha": "<sha_of_a_commit_belonging_to_OrgB/victim-repo>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC(SECRET_A, body)`.
4. POST to `/github/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner = "OrgA"`, verifies against `SECRET_A` → succeeds [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit belonging to `OrgB` — and calls `create_status_from_github!`, injecting a forged `success` status onto a commit the attacker never had write access to [4](#0-3) .

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
