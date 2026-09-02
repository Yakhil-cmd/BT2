### Title
Webhook signature verification binds to `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` (or no repository check at all) — cross-organization/cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple tenant GitHub organizations behind a single instance, each with its own GitHub App/webhook secret [1](#0-0) , tested via `test/dummy/config/secrets_double_github_app.yml` [2](#0-1) . The webhook signature check selects which organization's HMAC secret to verify against using `repository.owner.login` (falling back to `organization.login`) from the *unverified* JSON body [3](#0-2) . Once the signature passes, the event handlers resolve which `Repository`/`Stack`/`Commit` to mutate using a **different, uncorrelated** payload field — `repository.full_name` — or, in the `status` handler's case, no repository scoping at all. Nothing enforces that the organization whose secret validated the signature actually owns the repository that gets acted upon. This is the same class of bug as the reference report: two values (the field the trust decision is based on, and the field the effectful operation is based on) are supposed to be equivalent but are never actually checked against each other.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and its `webhook_secret`) via:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 
and only checks the HMAC of the whole raw body against that organization's secret [5](#0-4) .

Handlers however resolve the target repository/stack from a **separate** field:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end

def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [6](#0-5) 

`repository.owner.login` and `repository.full_name` are two independent keys inside the same JSON body and are never cross-checked against each other by the controller or any handler. Because the whole raw body — including both fields — is what gets HMAC-signed, an attacker who legitimately knows **any one** configured organization's `webhook_secret` (e.g., they administer their own tenant org's GitHub App on the same shared Shipit instance) can craft a payload where:
- `repository.owner.login` == "their own org" (so the correct/known secret is selected and verification passes), while
- `repository.full_name` == "victim-org/victim-repo" (an org/repo they have no GitHub access to and no Shipit privileges for).

`PushHandler` then does:
```ruby
stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
``` [7](#0-6) 
operating on the victim org's stacks using an attacker-supplied `after` SHA.

`CheckSuiteHandler` similarly scopes only by `repository.full_name`-derived `stacks`, letting the attacker schedule check-run refreshes for arbitrary victim commits [8](#0-7) .

`StatusHandler` is worse — it does not even scope by repository at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [9](#0-8) 
This means that once *any* configured organization's webhook secret is used to sign the request, the attacker can inject a commit status (including `state: success`) for **any commit SHA in the entire Shipit database**, regardless of which repository/organization that commit actually belongs to.

`Repository.from_github_repo_name` performs a plain DB lookup with no relation to which organization authenticated the request [10](#0-9) , confirming that repository resolution is completely decoupled from the verified-organization identity.

### Impact Explanation
This breaks the binding: `verified_organization (repository.owner.login) == repository_acted_upon (repository.full_name / commit lookup)`. Before the attack, only GitHub itself (holding org X's real webhook secret) can push, status, or check-suite events for org X's repositories, and only GitHub holding org Y's secret can do so for org Y. After exploiting this gap, a party who legitimately possesses org X's webhook secret (an unprivileged party with respect to org Y, no Shipit session, no `ApiClient` token, no GitHub write access to org Y) can:
- Forge a "success" CI status on an arbitrary commit belonging to another tenant's repository, which can defeat CI-gating (`Commit#deployable?`-style checks) used before deploys/merges.
- Force `GithubSyncJob`-style resynchronization of another tenant's stack with an attacker-chosen `expected_head_sha`.
- Trigger check-run refresh workflows against another tenant's commits.

This maps to the in-scope Critical impact "cross-repository writes" / "an unauthorized deploy, rollback or merge," since falsified commit statuses/pushes can be used to satisfy deploy-readiness gates on repositories the attacker has no legitimate access to.

### Likelihood Explanation
Requires a Shipit deployment configured for multiple GitHub organizations (a documented, first-class, supported configuration — see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`). Given that setup, the only thing an attacker needs is the webhook secret of *any one* configured organization (which they may legitimately possess as an admin of their own, unrelated tenant org on the shared instance) — no Shipit account, GitHub write access to the victim repo, or privileged token is required. This is a realistic architecture for any multi-tenant Shipit deployment.

### Recommendation
- Short term: After signature verification, re-derive the organization from `repository.full_name` (or `organization.login` for org-scoped events) and assert it equals `repository_owner` used to select the verifying secret; reject the webhook (422) on mismatch.
- Additionally, have `StatusHandler` and other handlers scope lookups (`Commit`, `Stack`) by the repository/organization that was cryptographically authenticated, not by an independent, unauthenticated field of the same JSON body.
- Long term: Treat every value read out of the webhook payload that drives which record is mutated as untrusted unless it is provably the same value that determined the signing key.

### Proof of Concept
Given a multi-org Shipit instance with orgs `attacker-org` (attacker knows its `webhook_secret`, e.g. `s3cr3t-a`) and `victim-org` (target, unknown secret) each hosting a stack:

```
body = {
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },   # used to pick the verifying secret
    "full_name": "victim-org/victim-repo"   # used by PushHandler to pick the target stack
  }
}
signature = "sha1=" + HMAC_SHA1("s3cr3t-a", body.to_json)

POST /webhooks
X-Github-Event: push
X-Hub-Signature: <signature>
Body: <body.to_json>
```
`WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC check succeeds since the attacker legitimately knows that org's secret [5](#0-4) . `PushHandler#process` then resolves `stacks` from `payload.dig('repository','full_name')` = `"victim-org/victim-repo"` [6](#0-5)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack [7](#0-6) , despite the attacker never possessing `victim-org`'s webhook secret or any GitHub access to it. A similarly crafted `status` event with `state: success` for any known victim commit SHA succeeds via `StatusHandler`, which performs no repository check at all [9](#0-8) .

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
