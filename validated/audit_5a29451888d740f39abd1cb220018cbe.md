I found a concrete binding break in the multi-organization webhook path: the signature is verified against the secret of the organization named in `repository.owner.login`, but the repository/stack that is actually mutated is looked up separately by `repository.full_name`, with no check that the two agree.

### Title
Webhook signature is verified against the organization named in the payload, but events are applied to whatever repository `full_name` states, allowing cross-organization signature reuse - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-GitHub-App deployment (`config/secrets.yml` keyed by organization, e.g. `test/dummy/config/secrets_double_github_app.yml`), `WebhooksController#verify_signature` selects the HMAC secret to check with `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight out of the unauthenticated JSON body: `params.dig('repository', 'owner', 'login')`. [1](#0-0) [2](#0-1)  Once the request is verified, `create` dispatches to handlers with the same raw JSON `params`, and each handler independently resolves the target repository/stack via `payload.dig('repository', 'full_name')` [3](#0-2)  — a different field of the same payload, never cross-checked against `repository_owner`.

### Finding Description
This mirrors the CEI defect in the report: an untrusted, attacker-influenced field (there, the callback data used by `IFERC1155`; here, the `repository.full_name` field of a JSON body) is acted upon without being covered by the check that was supposed to gate the whole operation. The "Checks" step (HMAC signature verification) is bound to `repository.owner.login`; the "Effects" step (which stack gets a `GithubSyncJob`, a `Commit`/`Status` write, a `PullRequest` update, a `ReviewStack` archive/unarchive, etc.) is bound to `repository.full_name`. Nothing enforces `full_name.split('/').first == repository.owner.login`.

Shipit explicitly supports installing separate GitHub Apps per organization, each with its own `webhook_secret` [4](#0-3) [5](#0-4) . In that configuration, an attacker who controls (or has installed) their own GitHub App on `OrgAttacker` knows `OrgAttacker`'s `webhook_secret` and can compute a valid `X-Hub-Signature` for any payload of their choosing, because `verify_webhook_signature` only checks the HMAC over the raw body against that one secret [6](#0-5) . The attacker sets `repository.owner.login = "OrgAttacker"` (so `verify_signature` picks their own known secret) while setting `repository.full_name = "OrgVictim/victim-repo"` (so the handler resolves and mutates the victim's stack via `Repository.from_github_repo_name`). Because `check_if_ping`/`drop_unhandled_event`/`verify_signature` never compare these two payload fields, the request passes signature verification and is then routed to the victim stack.

### Impact Explanation
Depending on event type this lets an unprivileged outsider (who only needs to control/install their own low-privilege GitHub App on any organization configured in `secrets.yml`) forge state-changing webhook events against a stack they do not own: creating/altering commit `Status` rows used for merge/deploy gating, triggering `GithubSyncJob`/`RefreshCheckRunsJob` against the victim stack, or archiving/unarchiving `ReviewStack`s tied to victim pull requests. This crosses a repository boundary the signature check was meant to enforce — matching the report's rule "an organization that authenticated versus the repository that is written." It stops short of RCE/token exfiltration by itself, but it is an authentication-scoping bypass that lets one org's credentials mutate another org's Shipit-tracked state, which can be chained into unauthorized-looking status/CI manipulation on the victim stack.

### Likelihood Explanation
Requires the host application to be configured with more than one GitHub App/organization (a documented, supported configuration) and requires the attacker to control or have installed a GitHub App on at least one of the configured organizations, so they know that organization's `webhook_secret`. No Shipit session, `ApiClient` token, or private key theft is needed — only knowledge of the secret for an organization the attacker legitimately owns/administers, which is exactly the kind of "unprivileged" boundary crossing the rules ask about (their own org's credentials are being used to write into someone else's repository).

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#stacks`), assert that the organization used to select the verification secret matches the organization implied by `repository.full_name` before dispatching to handlers — e.g., reject the request if `repository_owner != full_name.split('/').first`. More generally, bind signature verification to the exact same fields used to resolve the target repository, rather than to a different sub-object of the same untrusted payload.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgAttacker` and `OrgVictim`, each with its own GitHub App and `webhook_secret`, per `docs/setup.md`'s "Using Multiple GitHub Applications" section [4](#0-3) ; attacker has installed/administers the `OrgAttacker` app and thus knows its `webhook_secret`.
2. Attacker builds a `push`/`status` JSON body where `repository.owner.login = "OrgAttacker"` but `repository.full_name = "OrgVictim/victim-repo"`.
3. Attacker computes `X-Hub-Signature` using `OrgAttacker`'s `webhook_secret` over the raw body, matching `verify_webhook_signature`'s HMAC check [6](#0-5) .
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgAttacker")` and passes [1](#0-0) .
5. `create` dispatches the same payload to e.g. `PushHandler`, which resolves stacks via `Repository.from_github_repo_name("OrgVictim/victim-repo")` and syncs the victim stack [7](#0-6) , or `status`/`check_suite`/PR handlers similarly act on `OrgVictim`'s repository/stack.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
