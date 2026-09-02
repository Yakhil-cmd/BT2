## Analysis

This confirms the exploit path. `Handler#stacks` and `Handler#repository_name` use `payload.dig('repository', 'full_name')` [1](#0-0)  — a completely different JSON field from the one used to select the HMAC secret in `WebhooksController#verify_signature`/`#repository_owner`, which reads `params.dig('repository', 'owner', 'login')` [2](#0-1) . Since GitHub App configs (and their `webhook_secret`) are keyed per organization [3](#0-2) , and this engine explicitly supports multiple orgs each with independent `webhook_secret` values [4](#0-3) , the signature is verified against the secret belonging to whichever organization the attacker names in `repository.owner.login`, while the actual repository acted upon by the handler is taken from the unrelated `repository.full_name` field, which is never covered by that check.

### Title
Webhook signature is verified against an attacker-chosen organization while handlers act on an unrelated repository field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification by reading `repository.owner.login` (or `organization.login`) out of the **unauthenticated** request body itself, then verifies the raw body against that org's `webhook_secret`. Every webhook handler, however, resolves the target repository/stack using a different field, `repository.full_name` [5](#0-4) . Because the field that authorizes the request (`repository.owner.login`) is never bound to the field that is acted upon (`repository.full_name`), an attacker who legitimately controls one Shipit-integrated GitHub organization (and thus legitimately knows that organization's `webhook_secret`) can forge a `push`/`status`/`check_suite` payload whose `repository.owner.login` matches their own org (so the signature check passes with their own secret) but whose `repository.full_name` names a repository belonging to a completely different organization configured on the same Shipit instance.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)   # from payload
verified = github_app.verify_webhook_signature(sig, request.raw_post)
``` [6](#0-5) 
`repository_owner` is taken straight from the JSON body [7](#0-6) , before the body has been authenticated. The signature only proves the whole raw body was HMAC-signed with the secret of *that named organization* — it says nothing about which repository the same payload's `repository.full_name` refers to.

Downstream, `Handler#stacks`/`#repository_name` look up the `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')` [1](#0-0) , and `PushHandler#process` triggers `stack.sync_github` for every matching stack/branch [8](#0-7) , which enqueues `GithubSyncJob` to fetch commits and write them into that stack using the app's installation token [9](#0-8) . `StatusHandler#process` similarly writes a `Status` onto any `Commit` matching the attacker-supplied `sha`, independent of organization [10](#0-9) .

This is a direct analog of the reported `ValidateVoteExtensions` bug class: a security-relevant total (there, voting power; here, "which secret authenticates this request") is computed from attacker-injected data (`repository.owner.login`) that is not bound to the data actually consumed by the state-changing logic (`repository.full_name`, `sha`). The equality that should hold — *organization whose secret authenticated the payload == organization that owns the repository the payload is applied to* — is never enforced.

### Impact Explanation
An attacker who is an admin/owner of Org A (one org configured in the multi-org `github:` secrets block, e.g. `OrgOne`/`OrgTwo` per `test/dummy/config/secrets_double_github_app.yml`) legitimately knows Org A's `webhook_secret` (it is configured by them when setting up the GitHub App for their own org). They can send a forged HTTP POST to `/webhooks` with `X-Github-Event: push`, `X-Hub-Signature` computed with Org A's secret over a body where `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/victim-repo"` (a repository belonging to a different organization/customer sharing the same Shipit instance). `verify_signature` passes because it only checks Org A's secret against the org named in the payload, which the attacker controls. The `push` handler then resolves `OrgB/victim-repo`'s `Stack` and triggers `GithubSyncJob`, which uses the app's own GitHub credentials to fetch commits from `OrgB/victim-repo` and ingest them as legitimate deploy-eligible commits, or (via `status`) forges CI/status state on arbitrary commits by sha across the whole instance. This crosses repository/organization trust boundaries the multi-org feature is meant to isolate, enabling cross-repository writes and manipulation of deploy-gating status without any credential belonging to the victim org.

### Likelihood Explanation
Exploitable by any unprivileged external attacker who administers just one of the (possibly many) GitHub organizations wired into a shared, multi-tenant Shipit instance — a configuration explicitly supported and documented (`docs/setup.md` "Using Multiple Github Applications", `test/dummy/config/secrets_double_github_app.yml`). No access to the victim org's secret, no Shipit session, and no `ApiClient` token are required; only knowledge of one's own legitimately-provisioned `webhook_secret` and the ability to send an arbitrary HTTP request to the public `/webhooks` endpoint.

### Recommendation
Bind the signature-selection organization to the same field the handlers use to resolve the target repository (`repository.full_name`), and reject the request if `repository.owner.login`/`organization.login` disagrees with the owner segment of `repository.full_name`. Alternatively, derive the verification org strictly from `repository.full_name`'s owner segment (splitting on `/`) rather than from a separate, independently-controllable JSON field, so the value used to select the secret and the value used to select the mutated resource are provably the same.

### Proof of Concept
1. Attacker legitimately administers `OrgA`, configured in Shipit's multi-org `github:` secrets with `webhook_secret: secretA`.
2. Victim `OrgB` (a different tenant/org configured on the same Shipit instance) owns repository `OrgB/victim-repo`, tracked by a `Stack`.
3. Attacker crafts JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#repository_owner` returns `"OrgA"`; `Shipit.github(organization: "OrgA").verify_webhook_signature` succeeds using `secretA`, which the attacker knows [11](#0-10) .
6. `PushHandler#stacks` resolves stacks for `repository.full_name = "OrgB/victim-repo"` via `Repository.from_github_repo_name` [1](#0-0)  and calls `stack.sync_github(expected_head_sha: params.after)` [8](#0-7) , enqueuing `GithubSyncJob` against `OrgB`'s stack despite the request being authenticated only for `OrgA`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-53)
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

    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
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
