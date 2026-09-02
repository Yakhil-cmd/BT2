### Title
Webhook signature verified against attacker-selected organization but push/status events acted on for repository/stack in a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the HMAC secret) used to validate `X-Hub-Signature` based on `repository_owner`, a value read straight out of the still-unauthenticated JSON body. The `Handler#stacks` method used by `PushHandler`, `StatusHandler`, etc. independently resolves the target `Stack`/`Repository` from a *different* field of the same unauthenticated body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so a payload can be signed with OrgA's webhook secret while acting on a stack that belongs to OrgB.

### Finding Description
`verify_signature` computes the app used for verification purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks the app up in the multi-org config and returns a `GitHubApp` whose `verify_webhook_signature` only compares the raw body's HMAC against *that org's* `webhook_secret`: [3](#0-2) 

Once the signature check passes, the raw JSON is dispatched to handlers unmodified: [4](#0-3) 

Handlers such as `PushHandler` resolve the affected `Stack` via `Handler#stacks`, which reads `repository.full_name` from the same payload, completely independent of `repository.owner.login` used earlier for signature selection: [5](#0-4) [6](#0-5) 

Shipit explicitly supports hosting multiple GitHub Apps for multiple organizations with independent `webhook_secret`s in a single deployment: [7](#0-6) [8](#0-7) 

The binding that should hold is: `organization authenticated by verify_signature == organization owning the repository/stack the handler writes to`. Because `repository_owner` (used to pick the verification key) and `repository.full_name` (used to pick the stack to mutate) are both read from the same unverified body but are never cross-checked against each other, an attacker who legitimately knows one org's webhook secret (e.g., because they administer a lower-trust GitHub organization that the operator has also onboarded onto the same Shipit instance) can forge a signature valid for that org while embedding `repository.full_name` pointing at a stack tracked under a different, higher-trust organization present on the same Shipit instance. `Shipit::Webhooks.for_event('push')` would then run `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)` on the victim org's stack — a genuine cross-organization write triggered with a signature meant only to authenticate the attacker's own org.

### Impact Explanation
This breaks the "organization authenticated versus repository written" binding explicitly called out in scope. A user/organization with legitimately configured but lower-trust access on a multi-tenant Shipit instance can trigger unauthorized state changes (e.g. forcing `sync_github` / resync of commits, membership/team writes via `MembershipHandler`, or check-suite refresh) on stacks/repositories belonging to a completely different GitHub organization hosted on the same Shipit deployment, without ever obtaining that organization's own webhook secret. This is a cross-organization write achieved purely through payload confusion, satisfying the "cross-repository writes" Critical-impact criterion.

### Likelihood Explanation
Exploitability requires the operator to run Shipit in the documented multi-organization mode (`docs/setup.md` "Using Multiple Github Applications") and requires the attacker to control (or have compromised) the webhook secret of at least one of the configured orgs — which is a supported, non-privileged configuration scenario in the repo (not a "you already have God-mode" precondition, since one org's secret is meant to only authorize events for that org). Given the multi-org feature exists specifically to let an operator federate several orgs' webhooks into one Shipit instance, the likelihood that `repository_owner` and `repository.full_name` diverge under attacker control is realistic and requires no additional privilege beyond membership/administration of one federated org.

### Recommendation
After selecting the `github_app` for verification, re-derive `repository_owner`/`organization` from the verified payload and assert that it matches the owner embedded in `repository.full_name` (or better, resolve the `Stack`/`Repository` strictly through the same org used for the signature check) before invoking any handler. Reject the webhook if the two disagree.

### Proof of Concept
1. Operator configures Shipit with two orgs, `OrgA` (attacker-administered/low trust) and `OrgB` (victim, higher trust), each with distinct `webhook_secret`s, per `docs/setup.md`'s multi-org config.
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using OrgA's `webhook_secret` (known to the attacker since they administer OrgA) over this exact raw body, and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'OrgA')` (from `repository.owner.login`) and successfully verifies the signature with OrgA's secret.
5. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name('OrgB/victim-repo')` and calls `stack.sync_github(expected_head_sha: ...)` on OrgB's stack — a write triggered by a signature that only authenticated OrgA.

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
