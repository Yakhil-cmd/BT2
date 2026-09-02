### Title
Cross-organization webhook forgery: webhook signature verified against `repository.owner.login` but writes are performed against the unrelated `repository.full_name` field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's webhook secret to validate a delivery against using one payload field (`repository.owner.login`/`organization.login`), while every webhook handler that actually mutates state (syncs commits, records statuses, archives/unarchives review stacks, refreshes check runs) resolves the target `Stack`/`Repository` using a completely different, unauthenticated payload field (`repository.full_name`). Because these two fields are never checked for consistency, a Shipit instance configured for multiple GitHub organizations lets a party who can produce a validly-signed payload for one organization forge webhook events that write to stacks belonging to a *different* organization.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` purely from the JSON body and uses it to pick the `GitHubApp`/secret used for HMAC verification: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only checks the HMAC against the secret configured for that specific organization: [3](#0-2) 

Shipit explicitly supports configuring multiple, independently-managed GitHub organizations on the same instance, each with its own `webhook_secret`: [4](#0-3) [5](#0-4) 

Once the signature passes for the organization named by `repository.owner.login` (or `organization.login`), the raw JSON is dispatched unchanged to handlers, none of which re-check that field. Every handler instead resolves the target repository/stack from `repository.full_name`: [6](#0-5) [7](#0-6) [8](#0-7) 

`Repository.from_github_repo_name` is a pure string lookup with no relationship to the organization that was actually authenticated. The `repository.owner.login` field used for signature selection and the `repository.full_name` field used for the write are two independent, attacker-supplied strings within the same unauthenticated JSON body; nothing enforces `full_name.split('/').first == owner.login`. This breaks the binding: `organization authenticated == repository written`.

Since the whole HTTP request (headers and JSON body) is fully attacker-controlled — the endpoint is a public, unauthenticated POST — anyone who can produce a payload whose HMAC matches *any one* configured organization's secret (including the case where that organization's `webhook_secret` is left unset, which is documented as optional and causes `verify_webhook_signature` to unconditionally `return true`) can set `repository.full_name` to point at a Stack belonging to a completely different, unrelated organization configured on the same instance and have Shipit act on it as if GitHub had sent a legitimate event for that repository.

### Impact Explanation
An attacker who can satisfy the signature check for organization A (trivial if A's `webhook_secret` is unconfigured, since that check is a no-op) can forge `push`, `status`, `check_suite`, or `pull_request` events for organization B's stacks by setting `repository.full_name` to `"orgB/repo"`. Concretely this allows:
- Forcing `GithubSyncJob` to run against an arbitrary stack (`PushHandler`) [9](#0-8) .
- Injecting fabricated commit CI status via the `status` event, and refreshing check runs via `check_suite`, both of which feed into commit "deployable" state used to gate continuous delivery — falsifying these can enable an unauthorized deploy through the continuous-delivery path.
- Archiving/unarchiving review stacks and altering pull-request-driven provisioning behavior for an unrelated organization's repositories [10](#0-9) .

This crosses a repository/organization trust boundary the engine is meant to enforce per its own multi-org documentation, satisfying the "unauthorized deploy/rollback" or "authentication bypass across repositories" bar.

### Likelihood Explanation
Requires a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration) and, in the strongest form, at least one organization with `webhook_secret` unset (also a documented, supported configuration since the field is optional). Given this is a documented deployment mode, not a misconfiguration outside the engine's control, the likelihood is realistic for any multi-tenant Shipit install.

### Recommendation
In `WebhooksController#verify_signature`/`create`, and in `Shipit::Webhooks::Handlers::Handler#repository_name`, cross-check that the organization used to select the verifying secret (`repository.owner.login`/`organization.login`) matches the owner segment of `repository.full_name` before dispatching to handlers; reject the request otherwise. Additionally, consider making `webhook_secret` mandatory (or refusing to boot without one) to remove the no-op verification path entirely.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (no `webhook_secret` set, or a known secret) and `OrgB` (has a Stack for `OrgB/prod-app`), per the documented multi-org config [4](#0-3) .
2. POST to `/webhooks` with header `X-Github-Event: push`, no/any `X-Hub-Signature`, and body:
```json
{"ref": "refs/heads/main", "after": "<attacker-chosen sha>", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/prod-app"}}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and, since `OrgA.webhook_secret` is unset, `verify_webhook_signature` returns `true` unconditionally [11](#0-10) .
4. `PushHandler` resolves the stack via `repository.full_name` = `"OrgB/prod-app"` [6](#0-5)  and triggers `stack.sync_github(expected_head_sha: ...)` for `OrgB`'s stack, even though the request was never authenticated for `OrgB`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```
