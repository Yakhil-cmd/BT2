### Title
Cross-organization webhook forgery via mismatched signature-verification org and payload-processed repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App webhook secret to validate a request against using `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), but the handlers invoked afterwards (`Shipit::Webhooks::Handlers::*`) act on unrelated fields of the same payload — `repository.full_name` (push/check_suite) or, in the case of `StatusHandler`, no repository scoping at all, just a raw `sha`. This is the same bug class as the reported DeFi issue: one field of a signed payload is used to authorize/validate, while a *different, uncorrelated* field is used for the actual state-changing action — breaking the equality that should hold between "the org whose signature was verified" and "the repository/commit that gets written."

### Finding Description
`verify_signature` in [1](#0-0)  does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is read from [2](#0-1) . This only proves that *some organization's* webhook secret matches the raw body — i.e. the request really came from an app installation on `repository_owner`'s org. It does **not** prove anything about which repository the payload's other fields describe.

The dispatched handlers, however, key off different, independently-attacker-controlled fields of the very same JSON body:
- `Shipit::Webhooks::Handlers::Handler#repository_name` uses `payload.dig('repository', 'full_name')` [3](#0-2) , which is a completely separate JSON key from `repository.owner.login` used for signature selection.
- `PushHandler#process` resolves stacks via that `repository_name`/`stacks` helper and calls `stack.sync_github(...)` [4](#0-3) .
- `CheckSuiteHandler#process` similarly resolves `stacks` from `repository.full_name` and schedules check-run refreshes [5](#0-4) .
- `StatusHandler#process` is worse: it does **no repository scoping whatsoever** — it matches purely by commit `sha` across the entire Shipit installation: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [6](#0-5) .

Because `Shipit.github(organization:)` is keyed by the attacker-supplied `repository_owner`/`organization.login` field, and in a multi-organization deployment each configured org has its own independent `webhook_secret` [7](#0-6) , an attacker who legitimately controls an app installation/webhook secret for **one low-trust organization** ("OrgA") registered in Shipit's `secrets.github` map [8](#0-7)  can:

1. Compute a valid `X-Hub-Signature` HMAC over a crafted JSON body using OrgA's known `webhook_secret`.
2. Set `repository.owner.login` (or `organization.login`) = `"OrgA"` so `verify_signature` picks OrgA's secret and passes.
3. Set `repository.full_name` = `"OrgB/victim-repo"` (any other org/repo tracked as a Shipit stack) for `PushHandler`/`CheckSuiteHandler`, or simply set `sha` to a known commit SHA of a victim stack for `StatusHandler` — since `StatusHandler` never checks any repository field at all.

The signature check in `verify_signature` only establishes trust in "this payload came from an app installed on OrgA," but the handlers then act on OrgB's stacks/commits because the org-authenticating field and the repository-acted-upon field are never cross-checked.

### Impact Explanation
This breaks the binding **"organization that authenticated" == "repository that is written"**, matching the report's core bug class exactly. Concretely:

- Via `StatusHandler`, an attacker who knows/guesses a target commit's SHA (trivial for public GitHub repos, since SHAs are not secret) can inject a forged `success` (or any) commit status for a commit belonging to a completely unrelated, more privileged organization's stack, using only credentials/signature material scoped to their own low-trust org. `create_status_from_github!` feeds directly into `Commit#deployable?` (`success? && !blocked?`) [9](#0-8) , and into `Commit#schedule_continuous_delivery`, which triggers `ContinuousDeliveryJob` when `deployable? && stack.continuous_deployment? && stack.deployable?` [10](#0-9) . On a stack with continuous deployment enabled and CI-status-gated safety, this allows an attacker to force an **unauthorized deploy** of a victim's repository by spoofing CI success without ever having valid credentials for that organization.
- Via `PushHandler`/`CheckSuiteHandler`, an attacker can trigger spurious `GithubSyncJob`/`RefreshCheckRunsJob` executions against arbitrary tracked stacks in other organizations, causing the app's own GitHub credentials to be used against those repos on attacker-chosen triggers (a cross-organization action-triggering primitive, though these two are more benign since they re-fetch truth from the GitHub API rather than trusting payload data directly).

This qualifies as a High/Critical-tier finding under the program rules ("unauthorized deploy") because it allows crossing an organizational trust boundary using only a lower-trust org's webhook secret to affect a higher-trust org's deploy pipeline — without any Shipit session, `ApiClient` token, or repository write access.

### Likelihood Explanation
Requires: (a) Shipit configured for multiple GitHub organizations (documented, supported multi-org setup [8](#0-7) ), (b) the attacker controls or can trigger webhook delivery for at least one org registered in that config (e.g., they administer a GitHub App installation/webhook on their own lower-trust org that Shipit also tracks), and (c) knowledge of a target commit SHA (public for public repos, or obtainable via other endpoints). All three conditions are realistic in a shared, multi-tenant Shipit deployment where different organizations are onboarded with differing trust levels — exactly the scenario the multi-org feature is designed for.

### Recommendation
After verifying the HMAC signature against the selected organization's secret, cross-validate that every repository/organization reference used by the downstream handler (`repository.full_name`, `repository.owner.login`, `organization.login`) is internally consistent, and additionally verify that the resolved `Repository`/`Stack` record's stored `owner` actually matches the organization whose secret validated the signature. Reject the webhook if `repository.owner.login` (used for verification) does not match the owner segment of `repository.full_name` (used by handlers). For `StatusHandler` specifically, scope the `Commit` lookup by the verified organization's repositories, not by `sha` alone.

### Proof of Concept
1. Shipit is configured with two orgs, `OrgA` (attacker-controlled) and `OrgB` (victim, has a stack with continuous deployment + required status checks).
2. Attacker knows the `webhook_secret` configured for `OrgA` (they can view/set it in the GitHub App settings for their own org installation).
3. Attacker finds the current HEAD sha of `OrgB/victim-repo`'s tracked branch (public commit history).
4. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim head sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" } }
}
```
   signing the raw body with `HMAC-SHA1(OrgA_webhook_secret, body)` as `X-Hub-Signature`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and the signature validates (attacker knows this secret).
6. `StatusHandler#process` runs `Commit.where(sha: "<victim head sha>")` — with no org/repo check — and creates a `success` status on `OrgB`'s commit, potentially triggering `schedule_continuous_delivery` and an unauthorized deploy of `OrgB/victim-repo`.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
