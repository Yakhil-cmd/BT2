### Title
Cross-organization webhook forgery via `repository.owner.login` vs `repository.full_name` binding mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify a webhook payload against based on `repository.owner.login` (or `organization.login`), but every webhook `Handler` (e.g. `PushHandler`, `StatusHandler`, PR handlers) resolves the *target* stack/repository using a separate field, `repository.full_name`, which is never cross-checked against the organization used for signature verification. In a multi-tenant Shipit deployment (multiple GitHub Apps/organizations configured under `secrets.github`), an org admin who legitimately knows their own org's `webhook_secret` can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` points at a completely different, unrelated organization's repository/stack. This is directly analogous to the AMM report's core flaw: a value that is *acted upon* (`repository.full_name` → stack resolution) is never covered by the same check that establishes trust (`repository.owner.login` → signature verification).

### Finding Description
`Shipit.github(organization:)` looks up the app config for the named organization and returns a `GitHubApp` whose `webhook_secret` is used to compute/verify the HMAC signature: [1](#0-0) 

`WebhooksController#verify_signature` derives that organization name purely from the payload itself: [2](#0-1) 

Note `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both are just JSON fields inside the attacker-supplied body, used only to pick *which secret* to validate the HMAC with.

Once the signature step passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the whole raw JSON to handlers: [3](#0-2) 

Every handler resolves the target repository/stack using a *different* field, `repository.full_name`, via the base `Handler` class: [4](#0-3) 

`Repository.from_github_repo_name` splits this string on `/` and looks up any repository/stack by owner+name with no relation to `repository.owner.login`: [5](#0-4) 

Concrete handlers such as `PushHandler` then act on stacks matched this way, e.g. queuing a GitHub sync: [6](#0-5) 

This is an intentional, documented multi-tenant feature — Shipit explicitly supports separate GitHub Apps (and separate `webhook_secret`s) per organization: [7](#0-6) [8](#0-7) 

So the binding that should hold is:
`organization used to select/verify webhook_secret (repository.owner.login)` == `organization/repository whose stack is written to (repository.full_name)`

But no code enforces this equality. An attacker who controls (or is the legitimate admin of) OrgOne — one tenant onboarded to the shared Shipit instance, hence in possession of OrgOne's `webhook_secret` — can:
1. Build a JSON payload with `repository.owner.login = "OrgOne"` and `repository.full_name = "OrgTwo/victim-repo"`.
2. Sign the raw body with OrgOne's `webhook_secret` (which they legitimately know, since they configured/received it for their own tenant).
3. POST it to `/github/webhooks` (or wherever `WebhooksController` is mounted).
4. `verify_signature` resolves `Shipit.github(organization: "OrgOne")` and validates the HMAC — it passes because the attacker signed correctly with their own secret.
5. The dispatched handler (e.g. `PushHandler`, `StatusHandler`) resolves the target using `repository.full_name = "OrgTwo/victim-repo"`, an org the attacker has no relationship with, and acts on OrgTwo's stack.

### Impact Explanation
This lets a tenant with no privileges over OrgTwo inject webhook events attributed to OrgTwo's repositories/stacks purely by controlling their own org's webhook secret. Concretely:
- `PushHandler` calls `stack.sync_github(expected_head_sha:)`, enqueuing `GithubSyncJob` for OrgTwo's stack on attacker's demand — forcing out-of-band synchronization/CI re-evaluation of another tenant's stack: [9](#0-8) 
- `StatusHandler` writes fabricated CI status (`create_status_from_github!`) against real commits of OrgTwo's stack purely from attacker-controlled JSON fields, which can influence merge-queue/deploy gating logic (`all_status_checks_passed?`, `allows_merges?`): [10](#0-9) [11](#0-10) 
- Combined with `continuous_deployment`/merge-queue configuration on OrgTwo's stack, forged/faked green statuses or forced syncs can influence whether an automatic deploy or merge is triggered for a repository the attacker does not otherwise control — this crosses into the "unauthorized deploy/merge" and "cross-repository writes" impact categories called out as in-scope Critical/High impacts.

This satisfies the required binding break (authenticated organization vs. written repository) and the required impact class (cross-tenant/cross-repository unauthorized action triggered without holding credentials for the victim org).

### Likelihood Explanation
Requires only that the attacker be a legitimate administrator/holder of *any* one tenant's GitHub App/webhook_secret in a multi-org Shipit deployment — a normal, unprivileged-relative-to-other-tenants position, not requiring compromise of GitHub, TLS interception, or any Shipit session/ApiClient credential. Multi-org configuration is a supported, documented deployment mode, so this is reachable whenever Shipit hosts more than one organization's stacks (a common real-world topology for a shared internal deploy tool). No rate limiting or additional secret is needed beyond what the attacker already legitimately possesses for their own org.

### Recommendation
In `WebhooksController#verify_signature` and/or in `Webhooks::Handlers::Handler`, enforce that the organization used to select the verifying `webhook_secret` matches the owner encoded in `repository.full_name` (and `organization.login` for org-level events) before dispatching to handlers — e.g. reject the payload if `repository.full_name.split('/').first.casecmp(repository_owner) != 0`. Alternatively, resolve the target repository/stack by joining on both the verified organization and the repository name, rather than trusting `repository.full_name` alone.

### Proof of Concept
1. Deploy Shipit with multi-org config, e.g. per `test/dummy/config/secrets_double_github_app.yml`: `OrgOne` and `OrgTwo`, each with its own `webhook_secret`.
2. Onboard `OrgTwo/victim-repo` as a stack; attacker only has access to `OrgOne`'s webhook secret (e.g. because they self-service configured `OrgOne`'s GitHub App).
3. Craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/victim-repo"
  }
}
```
4. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgOne_webhook_secret, body)>`.
5. POST to the webhooks endpoint with `X-Github-Event: push`.
6. `verify_signature` resolves `Shipit.github(organization: "OrgOne")` and validates successfully.
7. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgTwo/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, forcing a `GithubSyncJob` against OrgTwo's stack — demonstrating an unauthorized cross-tenant action triggered solely with OrgOne's credentials.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
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

**File:** app/models/shipit/stack.rb (L380-382)
```ruby
    def allows_merges?
      merge_queue_enabled? && !locked? && merge_status == 'success'
    end
```
