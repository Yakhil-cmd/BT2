### Title
Cross-Organization Webhook Forgery via Mismatched Signature-Verification Identity and Handler-Target Identity - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to verify the HMAC signature against using one field read from the untrusted JSON body, while `Handler#repository_name` (used by every webhook handler to resolve the target `Repository`/`Stack`) reads a *different* field from the same untrusted body. In a multi-organization Shipit installation, these two fields can be made to disagree, letting an unauthenticated attacker pick whichever organization's identity is easiest to satisfy for signature verification while directing the actual side effects at a different, unrelated organization's repositories/stacks.

### Finding Description
`verify_signature` resolves the GitHub App/secret to check against like this: [1](#0-0) 

and: [2](#0-1) 

`repository_owner` picks `params.dig('repository','owner','login')`, falling back to `params.dig('organization','login')` if absent.

Separately, every webhook handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the actual repository/stack to act on via a completely independent JSON path: [3](#0-2) 

`Repository.from_github_repo_name` then splits `owner/name` straight out of `repository.full_name`: [4](#0-3) 

Because the entire request body is attacker-controlled prior to signature verification, an attacker can craft a payload where `repository.owner.login`/`organization.login` (used for signature verification) names one organization, while `repository.full_name` (used by the handler to pick the actual stack to mutate) names a different organization/repository. Shipit explicitly supports multiple GitHub Apps configured per organization, each with its own independent `webhook_secret`: [5](#0-4) 

Critically, `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved app has no `webhook_secret` configured: [6](#0-5) 

This means: if *any* organization configured on the Shipit instance has a blank/unset `webhook_secret` (a state the setup docs treat as a normal, supported configuration — `webhook_secret: # nil`), an attacker can set `repository.owner.login`/`organization.login` to that unsecured organization to pass `verify_signature` trivially, while setting `repository.full_name` to `TargetOrg/target-repo` belonging to a *different*, properly-secured organization. `verify_signature` never re-checks that the organization it authenticated against matches the organization actually targeted by the handler logic, so `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs against the spoofed target repository using the full untrusted payload.

This breaks the trust binding: **organization authenticated (via `repository_owner`) ≠ repository actually written (via `repository.full_name` in `Handler#repository_name`)**.

### Impact Explanation
This allows an unauthenticated attacker to forge GitHub webhook events (push, status, check_suite, membership, pull_request, etc.) against any stack belonging to a securely-configured organization, as long as any other organization on the same Shipit instance has no `webhook_secret` set. Concretely this can:
- Trigger `sync_github` / merge-queue and deploy-relevant state transitions on stacks the attacker does not control (`PushHandler#process`) [7](#0-6) .
- Inject forged commit statuses / check-suite results that Shipit uses as CI-gating signals for deploys, since `StatusHandler`/`CheckSuiteHandler` also resolve their target via the same unauthenticated `repository.full_name` field.
- Create arbitrary `Team`/`User` records via the `membership` event handler.

Because this can be leveraged to influence which commits are treated as deployable/mergeable on a repository the attacker does not own, it maps to "an unauthorized deploy, rollback or merge" impact class.

### Likelihood Explanation
Exploitability depends on a specific but realistic and documented configuration: a multi-organization Shipit deployment where at least one configured organization has `webhook_secret` left blank (the setup docs and example secrets files explicitly show `webhook_secret: # nil` as a valid/expected value) alongside another organization that does configure a secret. In such deployments, the attack requires no credentials, no GitHub App private key, and no Shipit session — only knowledge of the two organization names, both of which are typically public GitHub org names visible in the Shipit UI/URLs. This is a low-effort, unauthenticated attack once the prerequisite configuration exists.

### Recommendation
`verify_signature` must ensure the organization/app used to verify the signature is the same one that the request will ultimately act against, not merely echo whatever the untrusted payload claims. Concretely:
- After (or instead of) resolving `repository_owner` for signature verification, derive it consistently from the exact same field (`repository.full_name`) that `Handler#repository_name` uses, so both signature verification and the handler act against the same organization.
- Reject (or treat as unverified/log-and-drop) any webhook whose resolved GitHub App configuration has no `webhook_secret` set, rather than treating a missing secret as an implicit "allow" — at minimum, do not allow a "no secret" organization's identity to be used to authorize actions against a different, secret-protected organization's repositories.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgOpen` (no `webhook_secret`) and `OrgSecure` (with `webhook_secret` set), matching the supported multi-app config shape in `test/dummy/config/secrets_double_github_app.yml`. `OrgSecure/target-repo` has a Shipit `Stack` registered.
2. As an unauthenticated attacker, send:
```
POST /github/webhooks
X-Github-Event: push

{
  "organization": { "login": "OrgOpen" },
  "repository": { "full_name": "OrgSecure/target-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
(Omit `repository.owner.login` so `repository_owner` falls back to `organization.login`.)
3. `verify_signature` calls `Shipit.github(organization: "OrgOpen")`; since `OrgOpen` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` header is required.
4. `PushHandler` resolves the target stack via `payload.dig('repository','full_name')` = `"OrgSecure/target-repo"`, and enqueues `sync_github(expected_head_sha: "<attacker-chosen sha>")` for that stack — despite the request never having been signed by `OrgSecure`'s webhook secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
