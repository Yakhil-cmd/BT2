### Title
Cross-organization webhook confusion: signature is verified against `repository.owner.login` but stack lookup uses the unbound `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit explicitly supports hosting multiple, independently-administered GitHub organizations from a single instance, each with its own GitHub App and `webhook_secret` [1](#0-0) , [2](#0-1) . `WebhooksController#verify_signature` selects which organization's secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) [3](#0-2) , [4](#0-3) . However, every event handler resolves the actual `Stack`/`Repository` to act on using a *different* field of the same signed JSON body: `payload.dig('repository', 'full_name')` [5](#0-4) , e.g. `PushHandler#process` [6](#0-5) .

### Finding Description
Because the webhook body is a single JSON blob entirely controlled by whoever crafts it, and HMAC-SHA1 is computed over the raw bytes of that same blob, a party that legitimately possesses the webhook secret for **their own** organization (`OrgA`) can craft a payload where:
- `repository.owner.login = "OrgA"` (used only to select the verification secret), and
- `repository.full_name = "OrgB/victim-repo"` (used by every handler to look up the target `Stack`/`Repository`).

`Shipit.github(organization: repository_owner)` will resolve to `OrgA`'s `GitHubApp`, `verify_webhook_signature` will pass because the HMAC is valid for `OrgA`'s secret over the attacker-crafted body [7](#0-6) , [8](#0-7) . The dispatch loop then invokes handlers with the full parsed payload [9](#0-8) , and every handler resolves the acted-upon repository purely from `repository.full_name`, with no cross-check against `repository.owner.login`/the organization whose secret validated the request [5](#0-4) .

This breaks the equality the design implicitly assumes: `organization that authenticated == organization owning the repository that is written`. Multi-org support in `lib/shipit.rb#github`/`github_app_config` is explicitly built for the case where different organizations are independently administered ("If you want to deploy code from multiple Github organizations...") [10](#0-9) , [1](#0-0) , so `OrgA`'s webhook secret is not something `OrgB` trusts, yet it can be used to write into `OrgB`'s stack state.

### Impact Explanation
An administrator/holder of `OrgA`'s GitHub App webhook secret (which is `OrgA`'s own credential, not a Shipit-wide secret) can forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events that are accepted as authentic and dispatched against **any other organization's** repository/stack tracked by the same Shipit instance, e.g.:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for `OrgB`'s stacks matching the forged branch [6](#0-5) , which can drive continuous-deployment/sync side effects on `OrgB`'s stack.
- `PullRequest` handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`) can archive, unarchive, or provision `OrgB`'s review stacks by supplying a forged `repository.full_name` while the signature is validated under `OrgA`'s key [11](#0-10) , [12](#0-11) .
- `MembershipHandler` can create arbitrary teams/users on the fly regardless of the authenticating org (per `Handler` base, it also only reads payload fields, not the org that signed the request).

This is a cross-repository/cross-tenant write: an entity that only controls its own organization's webhook trust boundary can cause writes/state transitions on another organization's `Stack` records, satisfying the "cross-repository writes"/"unauthorized deploy" Critical-impact category defined in scope.

### Likelihood Explanation
Likelihood is conditioned on the deployment actually hosting more than one organization's GitHub App under one Shipit instance — a configuration the project explicitly documents and supports (`config/secrets.development.example.yml`, `docs/setup.md` "Using Multiple Github Applications", `test/dummy/config/secrets_double_github_app.yml`) [2](#0-1) , [13](#0-12) . In that supported configuration, no privileged Shipit account, session, or `ApiClient` token is required — only knowledge of one (any) tenant's own legitimate webhook secret, which that tenant's own GitHub App admin necessarily has. The webhook endpoint (`/webhooks`) is unauthenticated apart from this per-organization signature check [14](#0-13) .

### Recommendation
After identifying which organization's secret verified the signature, re-validate that `payload.dig('repository', 'full_name')` (and `organization.login` where used) actually belongs to that same organization before dispatching to handlers — e.g., assert `repository.full_name.split('/').first.casecmp(repository_owner).zero?` in `WebhooksController#verify_signature`, or pass the verified organization into `Handler` and have `Repository.from_github_repo_name` reject/ignore repositories whose owner does not match the verified organization.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgA` (attacker-administered) and `OrgB` (victim), per the multi-org config schema [1](#0-0) .
2. Attacker, knowing `OrgA`'s `webhook_secret`, builds a `push` payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<any sha attacker wants OrgB's stack to think is expected>",
     "repository": {
       "owner": {"login": "OrgA"},
       "full_name": "OrgB/victim-repo"
     }
   }
   ```
3. Attacker signs the raw JSON body with `OrgA`'s webhook secret and sends it to `POST /webhooks` with `X-Github-Event: push` and the resulting `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, verifies successfully against `OrgA`'s secret [7](#0-6) .
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/victim-repo")` and triggers `sync_github` on `OrgB`'s stack [5](#0-4) , [6](#0-5) , even though the request was never signed by `OrgB`.

### Citations

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/controllers/shipit/webhooks_controller.rb (L1-16)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
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
