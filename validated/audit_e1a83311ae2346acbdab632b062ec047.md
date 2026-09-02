### Title
Webhook signature verification binds to `repository.owner.login` while all event handlers act on `repository.full_name`, allowing cross-organization stack sync/writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple GitHub Apps, one per organization, each with its own `webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml` and `lib/shipit.rb#github_app_config`). `WebhooksController#verify_signature` selects which app/secret to verify the HMAC signature against using `repository_owner`, derived only from `params.dig('repository', 'owner', 'login')` (or `organization.login`). However, every webhook handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, used transitively by `PushHandler` and the pull-request handlers) resolves the target `Stack`/`Repository` using a *different* field: `payload.dig('repository', 'full_name')`. Nothing in the controller or in `Handler` enforces that `full_name`'s owner segment matches `repository.owner.login`. An attacker who legitimately controls (and thus knows the webhook secret of) one configured organization can forge a raw POST to `/webhooks` that signs with their own org's secret while setting `repository.full_name` to a *different*, victim organization's repository, causing Shipit to sync/act on a stack it was never authorized to touch for that org.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
The signature is verified against the secret configured for `repository_owner`'s `GitHubApp` (`lib/shipit/github_app.rb#verify_webhook_signature`, using `SecureCompare.secure_compare`). This is the only authentication performed on the raw JSON body — the endpoint requires no session, `ApiClient` token, etc. (`skip_before_action :verify_authenticity_token`).

Once verified, the raw parsed `params` (the entire attacker-controlled JSON) is dispatched unmodified to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
```
`app/models/shipit/webhooks/handlers/handler.rb`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`app/models/shipit/webhooks/handlers/push_handler.rb` uses `stacks` (i.e. `repository.full_name`) to find matching stacks and call `stack.sync_github(expected_head_sha: params.after)` — this fetches/syncs the stack from GitHub using Shipit's own GitHub App credentials for that stack's repo, independent of which org's secret validated the request.

The binding that should hold is:
```
organization whose secret authenticated the request (repository.owner.login)
    ==
organization owning the repository the handler writes to (repository.full_name's owner segment)
```
Nothing enforces this equality. `repository.owner.login` and `repository.full_name` are two independent, fully attacker-controlled fields inside the same signed JSON body; an HMAC over the raw body proves only that *some* known org's secret was used to sign it, not that the acting repository belongs to that org. This is analogous to the reported bug class: a privileged actor (owner of a secret/keeper of a role) can act outside the boundary the architecture intends (deployer/owner able to upgrade *any* beacon instance, not just the one they should control) — here, an org's webhook credential can drive Shipit actions against a different org's tracked repository/stack.

### Impact Explanation
This crosses the "cross-repository writes" boundary explicitly called out as Critical impact. In a multi-org Shipit deployment (the officially documented and supported `secrets.yml` schema keyed by organization, per `github_app_config`/`secrets_double_github_app.yml`), an actor who is a legitimate admin of one configured GitHub App/org can force Shipit to run `GithubSyncJob`/`sync_github` against a *different* org's stack that is unrelated to their own org, without ever needing that other org's webhook secret. Depending on which handlers are reachable this can range from spurious/DoS-like syncs on someone else's stack to state-changing actions (e.g. archiving/unarchiving review stacks, updating pull request state, and stack synchronization) attributed to a repository the attacker does not control.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured with more than one GitHub App/org (a supported, documented configuration — not a misconfiguration), and (2) the attacker to legitimately administer at least one of those configured orgs' GitHub Apps (so they know that org's `webhook_secret`). No Shipit account, session, or API token is needed — this is an unauthenticated HTTP endpoint from Shipit's perspective, gated solely by an HMAC whose scope-selection logic is flawed. Constructing the forged payload is trivial (attacker fully controls both `repository.owner.login` and `repository.full_name` in the JSON they sign).

### Recommendation
- After selecting `github_app` via `repository_owner`, verify that `repository.full_name`'s owner segment matches `repository_owner` (or, more generally, look up the target `Repository`/`Stack` first and confirm its configured organization matches the org whose secret validated the signature) before dispatching to any handler.
- Alternatively, bind webhook secrets to the specific `Repository`/installation resolved from `full_name`, rather than trusting a same-payload `owner.login`/`organization.login` field for secret selection.

### Proof of Concept
Preconditions: Shipit configured with `github.OrgA` and `github.OrgB`, each with its own `webhook_secret` (per documented multi-org schema). Attacker administers OrgA's GitHub App (knows OrgA's `webhook_secret`) but not OrgB's. A stack tracking `OrgB/victim-repo` exists in Shipit.

1. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>`.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and verifies successfully against OrgA's secret.
5. `PushHandler#process` calls `Repository.from_github_repo_name("OrgB/victim-repo")`, finds the real stack, and enqueues `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` — an action on OrgB's stack triggered purely by OrgA's credentials. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
