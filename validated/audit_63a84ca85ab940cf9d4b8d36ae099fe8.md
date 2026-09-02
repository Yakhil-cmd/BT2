### Title
Webhook organization used for signature verification is decoupled from the repository acted upon, enabling cross-organization writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a webhook against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) . Once the signature is accepted, every event handler instead resolves the target `Repository`/`Stack` to write to using a *different* field of the same payload: `payload.dig('repository', 'full_name')` [2](#0-1) . Shipit supports multiple independently configured GitHub organizations, each with its own `webhook_secret` [3](#0-2) [4](#0-3) . Because the field used to pick "which secret proves authenticity" (`repository.owner.login`) is not the same field used to pick "which repository gets acted upon" (`repository.full_name`), an attacker who legitimately controls one onboarded organization's webhook secret can forge a payload that verifies against their own organization while causing writes against a completely different organization's repository.

### Finding Description
This is the same bug class as the reported `give_coin` issue: a security-relevant decision is bound to the wrong field of an attacker-influenced payload, producing an equality mismatch between the credential that authorizes the action and the resource the action is performed on.

- Authentication side: `Shipit.github(organization: repository_owner)` retrieves the `GitHubApp` for the organization derived from `repository.owner.login`/`organization.login`, and `verify_webhook_signature` validates the HMAC of the raw body against that organization's `webhook_secret` [5](#0-4) [6](#0-5) .
- Execution side: every handler (`PushHandler`, `StatusHandler`, all `PullRequest::*Handler`s) resolves the `Repository`/`Stack` to mutate via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` [2](#0-1) [7](#0-6) [8](#0-7) .

The equality that should hold is:
`organization that signs/authenticates the request == organization that owns the repository being written to`

Nothing in the code enforces this. `repository.owner.login` and `repository.full_name`'s owner segment are two independently-settable JSON fields inside the same signed body — the signature only proves "this exact byte sequence was produced by whoever holds Organization X's `webhook_secret`", not "the repository referenced inside this payload belongs to Organization X." A legitimate customer/org (e.g. "OrgA") that is onboarded to this multi-tenant Shipit instance and therefore knows or can trigger delivery with its own `webhook_secret`, can send (or have their real GitHub App deliver, then replay/modify before it reaches Shipit if any proxy is involved, or more directly: simply configure their own GitHub webhook delivery payload since they control their own repo's webhook config) a payload where:
- `repository.owner.login` = `"OrgA"` (so `verify_signature` picks OrgA's `webhook_secret` and passes)
- `repository.full_name` = `"OrgB/victim-repo"` (an unrelated, unauthorized organization's repository tracked by the same Shipit instance)

This passes signature verification (bound to OrgA) while the handler acts on OrgB's `Stack`/`Repository`.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding called out in scope. Concretely, an attacker who only has legitimate control over their own onboarded organization's webhook secret can cause writes against another tenant's repository state:
- `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` for the victim's stacks/branches [9](#0-8) .
- `PullRequest::OpenedHandler`, `ReopenedHandler`, `LabelCapturingHandler`, `ClosedHandler` create/archive/unarchive review stacks and mutate PR/label state for the victim repository [10](#0-9) [11](#0-10) .
- `StatusHandler#process` injects forged commit statuses onto arbitrary commits belonging to any tracked repository, regardless of the authenticating org, since `Commit.where(sha: params.sha)` is not scoped by repository at all [12](#0-11) .

This is a cross-repository/cross-organization write in a multi-tenant deployment of the engine, matching the in-scope "Critical: cross-repository writes" impact.

### Likelihood Explanation
This only applies to deployments using Shipit's multi-organization GitHub App configuration (each org with its own `webhook_secret`), which the engine explicitly supports and documents [3](#0-2) . Any organization/customer already onboarded onto the same Shipit instance (an "unprivileged" party relative to other tenants, requiring no Shipit session, API token, or GitHub App private key) can exploit this purely by shaping the payload it sends/has delivered under its own, legitimately-known webhook secret. No cryptographic material belonging to the victim organization is needed.

### Recommendation
Bind the organization used for signature verification to the same repository record used for writing. Concretely, `Handler#stacks`/`Handler#repository_name` should re-derive (or the controller should pass through) the verified organization, and reject/ignore the event if `repository.full_name`'s owner does not match the organization whose secret validated the signature. Do not allow `repository.owner.login` (used only for secret selection) and `repository.full_name` (used for the actual write) to diverge — validate that the resolved `Repository`'s owner equals `repository_owner` before any handler runs.

### Proof of Concept
1. Configure Shipit in multi-org mode with `OrgA` and `OrgB` (`secrets.github` keyed by org, each with its own `webhook_secret`), both with repositories tracked as Shipit `Stack`s — as shown in the test fixture layout [4](#0-3) .
2. As the operator/owner of OrgA (who legitimately knows OrgA's `webhook_secret`), construct a webhook POST to `/webhooks` with `X-Github-Event: push` and body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Sign the raw body with `OrgA`'s `webhook_secret` and set `X-Hub-Signature` accordingly.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature [1](#0-0) .
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/victim-repo")` and triggers `sync_github` on OrgB's stack [2](#0-1) [9](#0-8) , despite the request never being authenticated as belonging to OrgB.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
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
