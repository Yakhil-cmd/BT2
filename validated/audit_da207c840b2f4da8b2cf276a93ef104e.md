This confirms the vulnerability class: `WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using `repository_owner`, which is read directly from the **unverified** JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), before the signature has been checked [1](#0-0) . The actual repository that handlers act on is looked up separately from `payload.dig('repository', 'full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`, with no cross-check that this repository actually belongs to the organization whose secret validated the signature [2](#0-1) .

### Title
Webhook signature verification binds to attacker-controlled organization field while handlers act on a different attacker-controlled repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multiple GitHub Apps/organizations, each with its own `webhook_secret` [3](#0-2) . `WebhooksController#verify_signature` picks *which* secret to verify the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted, not-yet-verified JSON body [4](#0-3) . Once the signature is confirmed against *that* org's secret, the event handlers independently re-read `repository.full_name` from the same body to decide which `Stack`/`Repository` to mutate [2](#0-1) , [5](#0-4) . Nothing enforces that the `full_name`'s owner segment matches the `repository.owner.login` (or `organization.login`) that was used for signature selection.

### Finding Description
The trust binding that should hold is: **organization whose secret authenticated the request == owner of the repository the handler writes to**. Before the fix, this is violated: any principal who legitimately controls a webhook secret for *some* organization configured in Shipit (e.g., they administer their own GitHub org/app that a Shipit instance also serves, as shown in the multi-org config example `test/dummy/config/secrets_double_github_app.yml` with `OrgOne`/`OrgTwo` [6](#0-5) ) can craft an arbitrary JSON payload where `repository.owner.login`/`organization.login` names their own org (so the signature check passes with a secret they legitimately possess) while `repository.full_name` names a completely different repository/owner tracked by the same Shipit instance. Because `Handler#repository_name` and `PushHandler`, `StatusHandler`, and PR handlers all key off `full_name` alone [2](#0-1) , [7](#0-6) , the forged payload is accepted and processed against the victim repository's `Stack`, even though it was authenticated with the attacker's own organization's secret rather than the victim organization's.

### Impact Explanation
An attacker with a legitimate webhook secret for one configured GitHub organization can forge `push`, `status`, `pull_request`, or `membership` events that are processed as if they came from a different, victim repository/organization also configured on the same Shipit instance. This can trigger `GithubSyncJob` to sync fabricated commits, drive continuous-deployment sync (`push` handler → `stack.sync_github`), or open/close/label review-stack pull requests for a repo the attacker does not control [8](#0-7) . This crosses a repository boundary using credentials scoped to a different repository/org, matching the "cross-repository writes" / unauthorized-deploy class of impact called out in scope.

### Likelihood Explanation
Requires the attacker to already possess a valid webhook secret for at least one organization/repository configured on the target Shipit instance (a realistic scenario for any Shipit deployment serving multiple independent GitHub orgs/apps, as explicitly documented and supported: "Using Multiple Github Applications" [9](#0-8) ). No Shipit session, ApiClient token, or GitHub write access to the victim repository is needed — only control of one's own org's webhook secret and the ability to POST to the shared `/webhooks` endpoint.

### Recommendation
After `verify_webhook_signature` succeeds, re-derive the organization from the same field used for the actual handler lookup (`repository.full_name`'s owner segment, or the `Repository` record it resolves to) and assert it matches the organization whose secret validated the signature. Reject the request (422) if they diverge, rather than trusting `repository.owner.login`/`organization.login` and `repository.full_name` as independent, unlinked fields.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker controls `OrgOne`'s webhook secret (e.g., is an admin of a GitHub App/org legitimately registered with this Shipit instance).
3. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "OrgOne" },
       "full_name": "OrgTwo/victim-repo"
     }
   }
   ```
4. Attacker computes `X-Hub-Signature` using `OrgOne`'s webhook secret over this exact payload.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgOne")` and successfully verifies the signature [1](#0-0) .
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgTwo/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack [8](#0-7) , even though the request was authenticated only with `OrgOne`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-45)
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
