### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the unrelated, unbound `repository.full_name` / `organization.login` fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check `X-Hub-Signature` against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) inside the attacker-supplied JSON body itself. However, every webhook `Handler` (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, etc.) resolves the target `Stack`/`Team` using a *different* field of the same body — `repository.full_name` (via `Handler#repository_name`) or `organization.login`/`team.id` — with no requirement that these match `repository.owner.login`. In a multi-organization deployment, this breaks the trust binding "organization whose signature was verified" == "repository/organization actually written to."

### Finding Description
`Shipit.github(organization:)` in `lib/shipit.rb` looks up a `GitHubApp` per organization key from the multi-org `secrets.github` hash [1](#0-0) . `GitHubApp#verify_webhook_signature` deliberately treats a missing `webhook_secret` as "always valid": `return true unless webhook_secret` [2](#0-1) . This is a documented, supported configuration — the setup docs and example secrets files explicitly show `webhook_secret: # nil` as valid per-organization config in the multi-app schema [3](#0-2) , and the project's own multi-org test fixture sets `webhook_secret: # nil` for both configured organizations [4](#0-3) .

`WebhooksController#verify_signature` picks which organization's secret to validate against using data taken from the payload under test, not any authenticated source:
```
github_app = Shipit.github(organization: repository_owner)
...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

Meanwhile, every handler that actually performs an action resolves its target using an entirely different field of that same body:
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, and `stacks` looks up `Repository.from_github_repo_name(repository_name)` [6](#0-5) .
- `PushHandler#process` uses those `stacks` and `params.after` to trigger `stack.sync_github` [7](#0-6) , which enqueues `GithubSyncJob` to fetch and append new commits and eventually cache/deploy the spec [8](#0-7) .
- `MembershipHandler#process` grants/revokes `Team` membership using `params.organization.login` and `params.member.login`, independent of `repository_owner` [9](#0-8) . Team membership feeds directly into `Shipit.github_teams` OAuth authorization.
- `StatusHandler` and `CheckSuiteHandler` similarly act on `sha`/`head_sha` and `branches`/`head_branch` fields never checked against `repository_owner` [10](#0-9) [11](#0-10) .

Because `repository_owner` is derived from the raw attacker-controlled JSON body — the exact bytes that get HMAC-verified — an attacker who crafts their own POST to `/webhooks` (mounted per `config/routes.rb`, `resources :webhooks, only: :create` [12](#0-11) ) can set:
- `repository.owner.login` (or `organization.login`) to the name of any organization configured in `secrets.github` that has **no `webhook_secret` set** — causing `verify_webhook_signature` to return `true` for *any* signature header, including a garbage one or none at all.
- `repository.full_name` / `organization.login` used by the handler to whatever *other* organization/repository/team is actually tracked by the Shipit install (which may have a real, secret-protected GitHub App).

The equality the deployment trust model needs is: *organization whose webhook secret was cryptographically verified* == *organization/repository the handler subsequently writes to*. This code breaks that equality because the two lookups read different JSON keys from the same untrusted body, with no cross-check that `repository.owner.login` is a prefix of `repository.full_name` or matches `organization.login`.

### Impact Explanation
This allows an unauthenticated, unprivileged network attacker (no Shipit session, no `ApiClient` token, no GitHub App private key, no `webhook_secret`) to forge arbitrary `push`, `status`, `check_suite`, `pull_request`, and `membership` webhook events against *any* stack/repository/team tracked by a Shipit instance that has multiple GitHub organizations configured where at least one organization omits `webhook_secret` (a state the project's own documentation and fixtures present as normal/supported). Consequences include:
- Forged `push` events driving `GithubSyncJob`/`sync_github` against a victim stack, causing Shipit to fetch and append attacker-influenced commit history and potentially trigger downstream automated deploy/merge flows — an unauthorized deploy/rollback vector.
- Forged `membership` events adding an attacker-controlled GitHub login to a `Team` used for `Shipit.github_teams` OAuth authorization, escalating into that authorization boundary.
- Forged `status`/`check_suite` events manipulating commit CI status/check state that gates merges and deploys.

This satisfies the High-impact criteria ("escalation into `Shipit.github_teams` authorization", "unauthorized deploy") and, via the `push`→sync/deploy path, borders on the Critical "unauthorized deploy" bucket.

### Likelihood Explanation
Exploitability requires only that the deployment use the documented multi-organization `secrets.github` schema with at least one configured organization lacking a `webhook_secret` — an explicitly supported, documented configuration, not a misconfiguration outside the engine's own code/docs. No credentials, sessions, or secrets are needed by the attacker; only network access to the public `/webhooks` endpoint is required.

### Recommendation
- In `WebhooksController#verify_signature`, do not let payload-derived data pick the trust boundary that then goes unchecked elsewhere: after verifying the signature for the resolved `repository_owner`, require that every handler's target field (`repository.full_name` owner segment, `organization.login`) be consistent with the same `repository_owner`/organization used for verification, rejecting the request otherwise.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in multi-organization mode; either require a secret per organization or fail closed.
- Centralize "which organization owns this event" resolution into a single trusted value used consistently by both signature verification and all `Handler` subclasses.

### Proof of Concept
Preconditions: Shipit configured with multi-org `secrets.github` where org `OrgWithoutSecret` has `webhook_secret` unset/nil, and a victim stack tracked under `victim-org/victim-repo` (any org, secret or not).

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgWithoutSecret" },
    "full_name": "victim-org/victim-repo"
  }
}
```
- `repository_owner` resolves to `"OrgWithoutSecret"` → `Shipit.github(organization: "OrgWithoutSecret")` → `verify_webhook_signature` returns `true` unconditionally because that org has no `webhook_secret` [2](#0-1) .
- `PushHandler` then resolves stacks via `repository.full_name = "victim-org/victim-repo"` [6](#0-5)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim stack, entirely bypassing GitHub App authentication for that organization.

Note: I was unable to execute this against a running instance; the analysis is based on static code tracing across `WebhooksController`, `GitHubApp#verify_webhook_signature`, `Shipit.github`, and the `Handler` subclasses cited above, which is a documented and testable code path but not dynamically verified here.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-44)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```
