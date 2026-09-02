### Title
Webhook signature verification selects the trust secret by an unverified `repository_owner` field, decoupled from the repository the payload handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App / organization secret to use for HMAC verification based on `repository_owner`, a value read directly out of the still‑unauthenticated JSON body. The event handlers that subsequently run, however, select the target `Stack`/repository using a different field from the same unauthenticated body (`repository.full_name`). Because these two lookups are independent, a request can be crafted so that signature verification is checked against (and satisfied by) one organization's configuration while the actual mutation is applied to a different organization's/repository's stacks. This is the same class of bug as the report's `migrate()` equality check: the code assumes two values that should be bound together (the authenticated identity and the entity acted upon) are always equal, but never enforces that binding.

### Finding Description
`verify_signature` derives the org used to pick a secret purely from body content, before the signature has been proven valid: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per‑organization config, and if that organization's `webhook_secret` is blank, `GitHubApp#verify_webhook_signature` short‑circuits to `true`, disabling verification entirely for that credential selector: [3](#0-2) [4](#0-3) 

Meanwhile, once the request passes `verify_signature` (correctly or via the `webhook_secret`‑absent bypass), `WebhooksController#create` hands the *entire unauthenticated JSON body* to the registered handlers: [5](#0-4) 

Every handler resolves the repository/stack to mutate from `payload.dig('repository', 'full_name')` — a completely different field than the one used for signature-secret selection: [6](#0-5) [7](#0-6) 

The binding that should be an equality — "the organization whose secret validated this signature" == "the repository/organization whose stacks this payload is allowed to mutate" — is never checked. `Shipit` explicitly supports multiple independently configured GitHub organizations, each with its own (optional) `webhook_secret`, confirmed by the multi-org docs and dummy config where multiple orgs each declare their own (possibly empty) `webhook_secret`: [8](#0-7) [9](#0-8) 

### Impact Explanation
If any organization configured on the instance has no `webhook_secret` set (the docs describe it as "optional"), an unauthenticated attacker can send a POST to `/webhooks` with `X-Github-Event` set to `push` (or `status`, `check_suite`, etc.), set `repository.owner.login`/`organization.login` to that unsecured organization (so `verify_signature` resolves a `GitHubApp` whose `verify_webhook_signature` unconditionally returns `true`), while setting the actual `repository.full_name` in the body to a *different, secured* organization's repository. `PushHandler` will then locate real `Stack`s for that targeted repository via `Repository.from_github_repo_name` and enqueue `GithubSyncJob` with an attacker‑chosen `expected_head_sha`, or `StatusHandler`/`CheckSuiteHandler`‑style handlers can inject arbitrary commit statuses/check results for arbitrary shas of that repository's commits. Depending on how `shipit.yml` gates deploys on statuses/checks, this can be used to falsify CI state and enable an unauthorized deploy of an unreviewed commit — i.e., cross-organization state manipulation without ever knowing the target org's real `webhook_secret`. This satisfies the "unauthorized deploy" / cross‑repository‑write class of impact.

### Likelihood Explanation
Exploitability depends entirely on operator configuration: the multi-organization webhook secret schema is a documented, supported configuration (`docs/setup.md`), and the example/dummy configs show `webhook_secret` frequently left blank ("optional"), so real deployments with at least one org lacking a secret are plausible. No credential, GitHub App key, or session is required — only knowledge of the target's `repository.full_name` and the name of one improperly-configured sibling organization on the same Shipit instance.

### Recommendation
Bind signature verification to the exact repository/organization the payload will act upon, not to a value chosen independently by the attacker:
- Use the same field (`repository.full_name` → derive owner from it) for both signature-secret selection and handler dispatch, or verify after dispatch that the resolved `Repository`'s owner matches the organization whose secret validated the signature.
- Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is unset for the app used, or require all configured organizations to have a secret; alternatively verify the signature against the secret of the organization owning the resolved repository, not the attacker-supplied `repository_owner`.

### Proof of Concept
1. Shipit is configured with two GitHub organizations (per `docs/setup.md`'s multi-app schema): `orgA` (no `webhook_secret` configured) and `orgB` (has a stack, `webhook_secret` set and unknown to attacker).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and no/garbage `X-Hub-Signature`, with body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha-that-exists-in-orgB-repo>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/protected-repo" }
}
```
3. `WebhooksController#verify_signature` computes `repository_owner` as `orgA` (from `params.dig('repository','owner','login')`), calls `Shipit.github(organization: 'orgA')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` — the request is accepted (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`; `lib/shipit/github_app.rb:76-77`).
4. `create` dispatches the body to `PushHandler`, which resolves stacks via `Repository.from_github_repo_name('orgB/protected-repo')` and enqueues `GithubSyncJob` with the attacker-chosen `expected_head_sha`, acting on `orgB`'s real stacks despite the attacker never possessing `orgB`'s `webhook_secret` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`; `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`).

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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
