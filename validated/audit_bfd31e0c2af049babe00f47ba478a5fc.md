### Title
Webhook signature is verified against the organization implied by `repository.owner.login`, but handlers act on the repository named by the (independently attacker-controlled) `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same trust-binding bug class as the `assignTeam` report: a value used to *authorize* an operation (`_team` used to gate `assignTeam`) is never re-checked against the value that is actually *acted upon* (`_team` passed to `createYeet`). In Shipit's multi-organization webhook flow, the organization whose secret is used to *authenticate* an inbound webhook is derived from `repository.owner.login`, while the handlers that mutate state derive the *target repository* from the separate `repository.full_name` field of the same JSON body, with no cross-check that the two agree.

### Finding Description
`WebhooksController#verify_signature` selects which organization's webhook secret to use for HMAC validation from `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`): [1](#0-0) [2](#0-1) 

Shipit explicitly supports one GitHub App/webhook secret **per organization**, each isolated: [3](#0-2) [4](#0-3) 

Once the signature check passes, `WebhooksController#create` dispatches the **entire raw JSON body** to the registered handlers: [5](#0-4) 

Handlers such as `PushHandler`, `StatusHandler`, `PullRequest::OpenedHandler`, and others resolve the target `Repository`/`Stack` from `params.repository.full_name` (a different sub-field of the same body), independent of the `repository.owner.login` field used to pick the signing secret: [6](#0-5) [7](#0-6) [8](#0-7) 

Nothing anywhere enforces `repository.full_name.split('/').first == repository.owner.login`. Because the GitHub HMAC signature covers the whole raw body, an attacker cannot forge a signature for organization B without B's secret — **but** an attacker who legitimately controls org A's webhook secret (e.g., an org-A admin who configured Shipit's webhook URL for their own org, which is a normal, unprivileged-relative-to-org-B action) can craft a payload where `repository.owner.login = "orgA"` (so `verify_signature` selects and validates against org A's secret) while `repository.full_name = "orgB/some-repo"` (so the handler resolves and mutates org B's `Repository`/`Stack`). This breaks the binding: *organization that authenticated (org A)* ≠ *repository that is written (org B)*.

### Impact Explanation
Depending on the handler invoked, this allows an org-A-privileged (but org-B-unprivileged) actor to:
- Trigger `stack.sync_github` on an org B stack via a forged `push` event routed through org A's valid signature [9](#0-8) 
- Inject fabricated commit statuses for org B commits via `StatusHandler` [10](#0-9) 
- Provision/archive org B review stacks via the `pull_request` handlers [8](#0-7) 

Since deploy/merge-queue behavior in Shipit is driven by these webhook-triggered state transitions, this is a cross-organization/cross-repository write achieved without holding org B's own webhook secret or repository access — an unauthorized cross-tenant mutation of deploy state.

### Likelihood Explanation
This only applies to multi-organization Shipit deployments (documented and tested configuration) [11](#0-10) [12](#0-11) . The attacker only needs the ability to send arbitrary HTTP requests with a valid HMAC computed from an org they legitimately administer in that shared Shipit instance — no GitHub App private key, no Shipit session, and no org-B credential are required. This matches "minimal effort... originate from a mistake or malicious intent" from the reference report.

### Recommendation
In `WebhooksController`, after determining `repository_owner` and verifying the signature, also validate — before dispatching to handlers — that every repository-bearing field in the payload (`repository.full_name`, and any repository references inside nested objects used by individual handlers) is owned by that same `repository_owner`. Reject the request (422) if `repository.full_name.split('/').first` does not case-insensitively match `repository_owner`.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, `orgA` and `orgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-app config).
2. As an admin of `orgA` (holder of `orgA`'s webhook secret only), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "orgB/victim-repo",
    "owner": { "login": "orgA" }
  }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC(orgA_webhook_secret, body)`.
4. POST to `/github/webhooks` (or the mounted webhook path) with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner = "orgA"`, fetches `Shipit.github(organization: "orgA")`, and validates successfully against the attacker-known `orgA` secret [1](#0-0) .
6. `PushHandler` resolves the stack via `Repository.from_github_repo_name("orgB/victim-repo")` (from `repository.full_name`, not `repository.owner.login`) and calls `sync_github` on `orgB`'s stack [6](#0-5) [9](#0-8) , demonstrating a cross-organization write authenticated with the wrong org's secret.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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
