### Title
Cross-Tenant Commit-Status Forgery via Webhook Signature/Repository Binding Mismatch — Unauthorized Deploy - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using the attacker-controlled JSON field `repository.owner.login` (or `organization.login`), while `Shipit::Webhooks::Handlers::StatusHandler#process` (and the base `Handler#repository_name`) act on a *different*, independently attacker-controlled field of the same payload — either an unscoped `Commit.where(sha:)` lookup or `repository.full_name` — with no code path that verifies these two fields are consistent. In a multi-org Shipit deployment (`test/dummy/config/secrets_double_github_app.yml` shows this is a supported topology), a party who legitimately knows the webhook secret for their own onboarded organization can forge a signed payload whose `repository.owner.login` matches their own org (so the HMAC check passes) but whose commit `sha`/`repository.full_name` targets a stack belonging to a completely different tenant organization.

### Finding Description
The binding that should hold is: **organization whose secret authenticated the request == organization/repository the handler is permitted to mutate**. This binding is never enforced.

- `verify_signature` derives the org purely from payload content: [1](#0-0) [2](#0-1) 

- The signature itself only proves the raw body was signed by *some* configured org's `webhook_secret` — it does not prove the payload was actually emitted by GitHub for that org, since the body is entirely attacker-supplied JSON: [3](#0-2) 

- `StatusHandler#process` resolves target commits with **no repository/organization scoping at all** — it matches by `sha` across the entire installation: [4](#0-3) 

- This directly and unconditionally creates a forged commit status: [5](#0-4) 

- A forged "success" status can satisfy `deployable?` and trigger `schedule_continuous_delivery`, which enqueues an actual deploy job: [6](#0-5) [7](#0-6) 

Multi-org configuration (each org with its own independent `webhook_secret`) is an explicitly documented/supported setup: [8](#0-7) [9](#0-8) 

### Impact Explanation
An attacker who legitimately administers Org A's GitHub App (and therefore knows Org A's `webhook_secret` — a value they configured themselves and is not privileged w.r.t. this engine) can sign an arbitrary JSON body. By setting `repository.owner.login: "OrgA"` (so `verify_signature` selects and successfully validates against Org A's secret) but choosing a `sha` value belonging to a commit in Org B's stack, they can forge a passing CI `status` (and/or `check_suite`) for a commit they do not control and have no legitimate GitHub access to. If that stack has `continuous_deployment` enabled and that status satisfies `ci.require`, this directly triggers `ContinuousDeliveryJob` → an unauthorized deploy of Org B's stack, executed with the app's real deploy credentials on the deploy host. This crosses the "organization that authenticated versus the repository that is written" boundary and results in an unauthorized deploy — Critical impact per the rules.

### Likelihood Explanation
This requires no privileged Shipit account, API token, or GitHub write access to the victim organization — only knowledge of a `webhook_secret` for *any one* organization configured in the shared Shipit instance, which is routine information for any tenant that legitimately onboarded their own GitHub App into that Shipit deployment. The `/webhooks` endpoint is intentionally public and unauthenticated apart from the HMAC check, and the vulnerable code paths (`verify_signature`'s org selection vs. `StatusHandler`'s unscoped `sha` lookup) are unconditionally reachable for every request that passes signature verification.

### Recommendation
- Cryptographically/logically bind the organization used for signature verification to the repository the handler is permitted to modify: after selecting the org via `repository_owner`, re-validate that `repository.full_name`'s owner matches `repository_owner` before dispatching to handlers, and reject webhooks that don't match the stack/org actually configured for the resolved repository's app.
- Scope `StatusHandler#process` (and `CheckSuiteHandler`) commit lookups by `repository.full_name` (i.e., only consider commits whose `stack.repository` matches the payload's declared repository, and that repository must belong to the org whose secret verified the request), instead of a global `Commit.where(sha:)`.
- Consider signing/validating a canonicalized `(organization, repository)` tuple rather than trusting independent unauthenticated fields of the same JSON body for different authorization decisions.

### Proof of Concept
1. Shipit is configured with two independent GitHub Apps/orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org config).
2. Attacker legitimately administers `OrgA`'s GitHub App and therefore knows `OrgA`'s `webhook_secret`.
3. Attacker finds (via Shipit's public stack pages or GitHub) the `sha` of an undeployed commit on a stack belonging to `OrgB`, which has `continuous_deployment` enabled and a `ci.require`d status context, e.g. `"ci/tests"`.
4. Attacker crafts a JSON body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" },
  "sha": "<OrgB commit sha>",
  "state": "success",
  "context": "ci/tests",
  "description": "forged",
  "created_at": "2026-09-01T00:00:00Z"
}
```
5. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
6. `verify_signature` resolves `repository_owner` = `"OrgA"`, loads `OrgA`'s app, and the HMAC check passes (signed with the known `OrgA` secret).
7. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the `OrgB` commit regardless of the org context — and calls `create_status_from_github!`, creating a forged success status.
8. If this satisfies `deployable?`/`ci.require` for `OrgB`'s stack, `schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, causing an unauthorized deploy of `OrgB`'s code using the Shipit deploy host's real credentials.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
