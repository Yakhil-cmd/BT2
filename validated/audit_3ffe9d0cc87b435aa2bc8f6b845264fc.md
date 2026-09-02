### Title
Webhook signature verification is scoped to `repository.owner.login`/`organization.login` while the actual write target is resolved from the independent `repository.full_name` field, letting a payload authenticated for one GitHub organization drive writes/deploys on any tracked repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which `GithubApp`/`webhook_secret` to validate the HMAC against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . Once that check passes, `create` dispatches the same raw JSON `params` to `Shipit::Webhooks.for_event(event)` handlers [2](#0-1) , all of which resolve the repository to act on via a *different* field, `payload.dig('repository', 'full_name')`, in the base `Handler` class [3](#0-2) . Nothing ties `repository.owner.login` (the value the signature check trusts) to `repository.full_name` (the value the write path trusts) — they are independent, fully attacker-controlled JSON fields in the same POST body.

### Finding Description
This is a direct analog of the reported bug class: a value that is acted upon (here, which `Repository`/`Stack` gets synced or driven, taken from `repository.full_name`) is never covered by the same trust check that gates the request (here, HMAC verification keyed off `repository.owner.login`/`organization.login`). Concretely:

- `lib/shipit/github_app.rb#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for the resolved organization: `return true unless webhook_secret` [4](#0-3) . A `webhook_secret` is explicitly documented as optional per-organization [5](#0-4) , and Shipit supports multiple simultaneously configured organizations, some with a secret and some without, as shown in the test fixture `test/dummy/config/secrets_double_github_app.yml` (both `OrgOne` and `OrgTwo` have `webhook_secret: # nil`) [6](#0-5) .
- All webhook handlers (`PushHandler`, PR handlers, etc.) locate the `Repository`/`Stack` to mutate purely from `repository.full_name` via `Repository.from_github_repo_name`, with no re-check that this repository belongs to the organization whose credential (or lack thereof) was used to pass `verify_signature` [3](#0-2) , [7](#0-6) .
- `PushHandler#process` takes the attacker-supplied `after` SHA and calls `stack.sync_github(expected_head_sha: params.after)` for every stack matching the target repo/branch [8](#0-7) , which (depending on stack configuration) can drive continuous deployment to that SHA.

So the binding the engine relies on — `organization authenticated == repository written` — does not hold: the "organization authenticated" side is `repository.owner.login`/`organization.login` in the JSON body, and the "repository written" side is `repository.full_name` in the same JSON body, and they can diverge freely because both are attacker-supplied and never cross-validated.

### Impact Explanation
An unprivileged internet requester (no Shipit session, no API token, no GitHub credential) who can craft an arbitrary POST to the public `/webhooks` endpoint (per `config/routes.rb`, unauthenticated by design) can forge a payload where `repository.owner.login` names a Shipit-configured GitHub organization that has no `webhook_secret` set (or whose secret was independently learned), while `repository.full_name` names a completely different, unrelated repository/organization tracked by the same Shipit instance. The signature check passes trivially (`return true unless webhook_secret`), and the push handler will then invoke `stack.sync_github` against the victim organization's stack with an attacker-chosen `after` SHA, potentially triggering an unauthorized sync/deploy on a repository the attacker has no legitimate relationship with. This crosses "unauthorized deploy" and "cross-repository writes" thresholds explicitly listed as Critical/High impact in the rules.

### Likelihood Explanation
Likely wherever a Shipit deployment tracks multiple GitHub organizations (a supported and documented configuration, per `docs/setup.md` and the multi-org test fixture) and at least one configured organization omits `webhook_secret` (explicitly documented as "optional"). No authentication, session, or GitHub credential is required by the attacker; only knowledge of one configured org name with no secret and the target's `owner/name` full_name, both of which are discoverable (e.g., from the Shipit UI, which lists tracked stacks/repositories).

### Recommendation
- Do not allow `verify_webhook_signature` to bypass verification silently when `webhook_secret` is blank; either require a secret for every configured organization or fail closed.
- After signature verification, re-derive the acting organization strictly from the verified value and assert it matches the organization portion of `repository.full_name` (or `organization.login`) before dispatching to handlers, rejecting any payload where these disagree.
- Avoid keying secret selection off attacker-controlled JSON fields at all; if multiple organizations must share one endpoint, disambiguate via a URL path segment or App installation ID resolved server-side, not payload content.

### Proof of Concept
1. Configure two organizations in `config/secrets.yml`: `victim-org` (has `webhook_secret: s3cr3t`) and `attacker-org` (no `webhook_secret` set), both with repositories tracked as Shipit stacks.
2. POST to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature` (or any junk value), body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `verify_signature` resolves `repository_owner` = `"attacker-org"`, looks up its `GithubApp`, and since it has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally [9](#0-8) .
4. `create` dispatches to `PushHandler`, which resolves the target repository from `repository.full_name` = `"victim-org/victim-repo"` [10](#0-9)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack [11](#0-10) , causing an unauthorized sync/deploy trigger on `victim-org`'s stack despite the request never being authenticated by `victim-org`'s credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
