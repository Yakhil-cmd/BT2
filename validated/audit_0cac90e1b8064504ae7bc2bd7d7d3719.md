[1](#0-0) 

### Title
Webhook signature verified against an attacker-chosen organization while the payload's `repository.full_name` (a different, unrelated org/repo) is what gets processed - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, which is read straight out of the unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`). Every downstream handler, however, resolves the actual `Repository`/`Stack` to mutate using a *different* field from the same attacker-controlled body: `repository.full_name`. Nothing ties these two fields together, so the organization whose secret authenticates the request is not guaranteed to be the organization whose repository/stack is acted upon.

### Finding Description
`verify_signature` computes: [2](#0-1) 
and [3](#0-2) 

`repository_owner` is taken from the request body itself, before any authentication has occurred, and is used only to pick which per-organization GitHub App config (`Shipit.github(organization: ...)`) supplies the `webhook_secret` for HMAC verification: [4](#0-3) 
Note that if that organization's config has no `webhook_secret` set, verification is a no-op (`return true unless webhook_secret`).

Once the signature check passes, `WebhooksController#create` dispatches the same raw params to the registered handler: [5](#0-4) 

Handlers resolve the target `Repository`/`Stack` using a completely different field of the same payload — `repository.full_name` — not the `repository.owner.login` used for signature selection: [6](#0-5) 

For example, `PushHandler` uses that resolved stack set to trigger a GitHub sync directly against the stack found via `full_name`: [7](#0-6) 

Shipit explicitly supports multiple organizations, each with its own GitHub App and independent `webhook_secret`, as shown in the fixture configuration used for testing this feature: [8](#0-7) 

The binding that should hold is: *organization whose secret validated the signature* == *organization/repository the request is permitted to mutate*. Because `repository.owner.login`/`organization.login` (used to pick the verification key) and `repository.full_name` (used to pick the mutated resource) are independent, attacker-supplied fields in the same unauthenticated JSON body, this binding is not enforced anywhere in the request path.

### Impact Explanation
In a multi-organization Shipit deployment, if any one configured organization has no `webhook_secret` configured (or the attacker otherwise knows/guesses that organization's secret while not knowing the secret of the target organization), an unauthenticated attacker can:
1. Send a POST to `/webhooks` with `X-Github-Event: push` (or `status`, `check_suite`, etc.).
2. Set `repository.owner.login` (or `organization.login`) to the organization whose secret is empty/known, so `verify_signature` succeeds trivially.
3. Set `repository.full_name` to `targetOrg/targetRepo` — a repository belonging to a *different*, properly-secured organization managed by the same Shipit instance.
4. The handler resolves stacks via `Repository.from_github_repo_name('targetOrg/targetRepo')` and acts on them (e.g. `stack.sync_github`, injecting forged commit statuses via `StatusHandler`, or triggering `RefreshCheckRunsJob` via `check_suite`), all without ever presenting a valid signature for `targetOrg`.

This is a cross-repository write / forged-trust-boundary bypass performed entirely through an unauthenticated endpoint, letting an attacker manipulate the state (sync status, commit statuses, CI gating) of a repository/organization that is supposedly protected by its own distinct webhook secret.

### Likelihood Explanation
Exploitability depends on the deployment running Shipit with more than one configured GitHub organization/App (a supported, documented configuration) where at least one org lacks a strong `webhook_secret` or the attacker can otherwise learn one org's secret while not knowing another's. This is a realistic misconfiguration scenario for larger multi-tenant Shipit deployments, and the code contains no cross-check tying the signature-verification organization to the mutated repository's organization, so the flaw is deterministic once that precondition holds.

### Recommendation
After verifying the signature for `repository_owner`, re-derive the organization from `repository.full_name` (or `organization.login`, whichever field the handler will actually use) and require it to match the organization used for signature verification; reject the webhook (422) on mismatch. Alternatively, verify the signature using the owner parsed from `repository.full_name` directly rather than `repository.owner.login`/`organization.login`, so a single authoritative field drives both key-selection and resource-resolution.

### Proof of Concept
Given a Shipit instance configured with two organizations (`OrgNoSecret` with no `webhook_secret`, and `OrgProtected` with a strong secret protecting `OrgProtected/app`):
```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "OrgNoSecret" },
    "full_name": "OrgProtected/app"
  }
}
```
`verify_signature` calls `Shipit.github(organization: "OrgNoSecret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no `X-Hub-Signature` header is even required. `PushHandler#process` then resolves stacks via `Repository.from_github_repo_name("OrgProtected/app")` and calls `stack.sync_github(expected_head_sha: "deadbeef")`, forging a sync event for `OrgProtected/app` despite never presenting a valid signature for `OrgProtected`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
