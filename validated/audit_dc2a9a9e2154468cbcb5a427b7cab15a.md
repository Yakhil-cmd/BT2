### Title
Webhook signature verification is scoped by `repository.owner.login`, but the target Stack/Repository is resolved from the unverified `repository.full_name` field — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the inbound signature against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). [1](#0-0)  Once verification passes, every webhook handler determines which `Repository`/`Stack` to act on using a completely different field of the same JSON body: `payload.dig('repository', 'full_name')`. [2](#0-1)  The engine never checks that the organization used to select/verify the signing secret is the same organization that owns the repository being mutated. This is the exact "organization authenticated versus repository written" binding called out as in-scope: the equality `org_verified(repository.owner.login) == owner_of(repository.full_name)` is never enforced.

### Finding Description
`Shipit.github(organization: repository_owner)` looks up a per-organization `GitHubApp` config (`app_id`, `webhook_secret`, etc.) keyed by the organization name embedded in the payload. [3](#0-2)  `GitHubApp#verify_webhook_signature` computes the HMAC using that org's `webhook_secret` — but critically, **if that org's `webhook_secret` is blank/unset, verification unconditionally returns `true` regardless of the actual signature header**: [4](#0-3) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Multi-organization configuration, including organizations configured with no `webhook_secret`, is a documented and tested engine feature (`test/dummy/config/secrets_double_github_app.yml` configures two orgs, `OrgOne`/`OrgTwo`, both with `webhook_secret: # nil`). [5](#0-4) 

Once past `verify_signature`, `WebhooksController#create` dispatches the raw payload to handlers: [6](#0-5)  and every handler (`PushHandler`, `PullRequest::*Handler`, etc.) resolves the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')`: [7](#0-6) [8](#0-7) 

**Before/after the attacker's request:**
- Before: signature verification is meant to guarantee that a webhook claiming to originate from organization `X` is genuinely signed by `X`'s secret, and the payload content (including which repo is targeted) is trusted as a unit because it's covered by that same HMAC.
- After: an attacker who can reach the public `/webhooks` endpoint (no GitHub credentials, no Shipit session, no API token required) crafts a raw POST body where `repository.owner.login` = an org configured in this Shipit instance with a blank `webhook_secret` (satisfying `verify_signature` trivially), while `repository.full_name` = any other org/repo tracked by the same Shipit instance (e.g. a privileged production stack). The handler layer never re-validates that `full_name`'s owner matches the verified `repository_owner`, so the forged event is processed against the unrelated, unverified repository.

### Impact Explanation
This breaks the deployment-trust binding between the organization whose secret authenticated the request and the repository the resulting write is applied to. Depending on the handler triggered, an unprivileged external attacker can: enqueue a `GithubSyncJob` for an arbitrary stack (`PushHandler`) [9](#0-8) , create/archive/unarchive Review Stacks and update `PullRequest` records tied to that stack [10](#0-9) [11](#0-10) , or inject fabricated commit `Status` records affecting deploy gating for that target stack. These are writes/state transitions on a repository/stack that was never covered by the signature the attacker actually satisfied — matching the "High: unauthenticated read of stack state" / potential escalation toward "unauthorized deploy" impact classes, since forged push/status events can influence which commits are considered deployable.

### Likelihood Explanation
Exploitability is conditioned on the deployment running Shipit's multi-organization configuration with at least one organization lacking a `webhook_secret` — a configuration explicitly supported and exercised by the test fixtures in this engine (not a "host application not mounting the engine as documented" scenario, since the multi-org/no-secret path is native, first-class, and tested code). Given that condition, no credentials of any kind are required: the endpoint is a public, unauthenticated controller (`skip_before_action :verify_authenticity_token`) reachable by anyone. [12](#0-11) 

### Recommendation
After resolving `repository_name`/`stacks` in `Handler`, verify that the owning organization of `payload.dig('repository', 'full_name')` matches the organization that was actually used to select and pass the signature check (`repository_owner`), rejecting the event otherwise. Alternatively, bind webhook signature verification and target-repository resolution to the same single field, and make `webhook_secret` mandatory per configured organization rather than allowing a silent verification bypass when it is blank.

### Proof of Concept
Given a Shipit instance configured with two organizations in `secrets.github`, `OrgA` (no `webhook_secret`) and `OrgB` (tracks a sensitive stack, has its own secret):

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/sensitive-repo"
  }
}
```

- `repository_owner` resolves to `"OrgA"` → `Shipit.github(organization: "OrgA")` succeeds and `verify_webhook_signature` returns `true` unconditionally (blank secret), regardless of any `X-Hub-Signature` header supplied. [4](#0-3) 
- `PushHandler#stacks` then resolves `Repository.from_github_repo_name("OrgB/sensitive-repo")` and enqueues a sync job for `OrgB`'s stack with the attacker-supplied `expected_head_sha`, even though nothing about this request was validated against `OrgB`'s actual GitHub webhook secret. [9](#0-8) [2](#0-1)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-15)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

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
