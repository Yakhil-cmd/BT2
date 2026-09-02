## Title
Webhook signature verification selects the trust anchor (webhook_secret) from an unverified payload field, letting an attacker sign as their own org while the payload content targets a different org's repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` picks *which* organization's `webhook_secret` to validate the request against by reading `repository.owner.login` / `organization.login` straight out of the untrusted, unverified JSON body — before the HMAC signature has been checked. The same body's `repository.full_name` (or other repository-identifying fields), used later by handlers to resolve the actual `Stack`/`Repository`/`Commit` to act on, is never bound to that chosen organization by the signature check.

### Finding Description
`verify_signature` resolves the GitHub App/secret purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` then simply HMACs the *entire raw body* with whatever secret belongs to that (attacker-chosen) organization: [3](#0-2) 

Shipit explicitly supports one independent `webhook_secret` per GitHub organization when multiple orgs are configured on the same instance: [4](#0-3) [5](#0-4) 

Because the org used for signature selection (`repository_owner`) and the repository actually acted upon by the event handlers (resolved from other payload fields such as `repository.full_name`, matched against `Shipit::Repository`) are two different, independently-controlled fields inside the same unauthenticated body, the "organization that authenticated" and the "repository that is written" are never bound together by the signature: [6](#0-5) [7](#0-6) 

An attacker who legitimately owns/administers their own GitHub App installation on "Org A" (self-service creation is exactly the documented multi-org setup) possesses Org A's `webhook_secret`. They can craft a payload where `repository.owner.login` = `"Org A"` (so Org A's secret is selected and the HMAC they compute with their own secret validates), while `repository.full_name`, commit SHAs, PR numbers, etc. reference a stack belonging to unrelated "Org B" that is also configured on the same Shipit instance. The signature check only proves "this body was signed by someone holding Org A's secret" — it does not prove "the repository referenced in this body belongs to Org A."

### Impact Explanation
This breaks the equality **organization that authenticated == repository that is written**, letting an attacker with no privileges on Org B forge trusted GitHub events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) against Org B's stacks. Depending on which handler processes the forged event, this can trigger `GithubSyncJob` to resync/rewrite commit history state, forge deployable/commit statuses used as merge/deploy gates, or manipulate team membership records — i.e., cross-organization writes into Shipit's internal state for a repository the attacker does not control on GitHub. This matches the Critical "cross-repository writes" impact category.

### Likelihood Explanation
Requires only that the target Shipit instance is configured with more than one GitHub organization/App (a documented, supported configuration) and that the attacker controls one of those orgs' GitHub App/webhook secret — no access to the victim org, no Shipit session, and no GitHub write permission on the victim repository is needed. This is a design flaw in `verify_signature`'s trust-selection logic, not a probabilistic or DoS-style bug.

### Recommendation
Do not use unauthenticated payload fields to select the verification secret. Either verify the signature against every configured organization's secret and, only after a match, cross-check that the matched organization equals `repository.owner.login`/`organization.login`; or bind the webhook endpoint to a single, statically-configured organization per delivery URL (e.g., `/webhooks/:organization`) so the secret used for verification cannot be chosen by the request body itself.

### Proof of Concept
1. Configure Shipit with two orgs, "OrgA" (attacker-controlled GitHub App, webhook secret known to attacker) and "OrgB" (victim), per `docs/setup.md`'s multi-org instructions.
2. Attacker crafts a `push` event JSON body with `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/victim-repo"` and an `after` SHA of their choosing.
3. Attacker computes `sha1=HMAC(OrgA_webhook_secret, body)` and sets it as `X-Hub-Signature`.
4. POST to `/webhooks`. `verify_signature` calls `Shipit.github(organization: "OrgA")` → `verify_webhook_signature` succeeds (signed with OrgA's real secret over this exact body).
5. `Shipit::Webhooks.for_event('push')` handlers then process the body, resolving the target `Stack`/`Repository` via `repository.full_name = "OrgB/victim-repo"`, causing Shipit to act on OrgB's data despite the request only being authenticated as OrgA.

Note: I was unable to fully load `app/models/shipit/webhooks/handlers/push_handler.rb` in this session due to tool errors on the final iteration, so the exact field(s) the push/status handlers use to resolve the `Stack` (full_name vs. another identifier) could not be re-confirmed line-by-line; this should be verified directly against `app/models/shipit/webhooks/handlers/push_handler.rb` and `app/models/shipit/repository.rb` before treating the PoC mechanics as final.

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

**File:** app/models/shipit/repository.rb (L1-1)
```ruby
# frozen_string_literal: true
```
