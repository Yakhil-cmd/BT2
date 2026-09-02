## Analysis

The bug class in the report is a **binding mismatch**: the value used to compute a security-relevant outcome (withdrawable assets) is decoupled from the value that should have been checked (bad debt / actual solvency), letting an attacker act on a field that was never validated against the thing that matters.

The strongest reachable analog in `shipit-engine` is in `WebhooksController#verify_signature`: the *organization* used to select the webhook secret for signature verification is read from an **unverified field of the raw JSON body**, and that field is not the same field the event handlers use to decide **which repository/stack is written to**. [1](#0-0) [2](#0-1) 

`repository_owner` is computed as `params.dig('repository','owner','login') || params.dig('organization','login')`, i.e. it falls back to an entirely different top-level JSON key (`organization`) when `repository.owner.login` is absent. This value picks which configured `GithubApp` (and therefore which `webhook_secret`) is used to verify `X-Hub-Signature`. [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization: `return true unless webhook_secret`.

Meanwhile, every webhook `Handler` resolves the **target stack/repository** from a completely different field, `payload.dig('repository', 'full_name')`: [4](#0-3) 

and `PushHandler#process` uses that repository's stacks to trigger a GitHub sync of commits: [5](#0-4) 

which enqueues `GithubSyncJob`, which fetches commits via the GitHub API and appends them to the stack's history, driving continuous-deployment/status logic: [6](#0-5) 

### The broken binding (equality that should hold but doesn't)

`organization_used_for_signature_verification == organization_that_owns_the_repository_being_written_to`

Before the attack: for legitimate GitHub-originated webhooks, `repository.owner.login` and `organization.login` (when present) always refer to the same org as `repository.full_name`, so the equality holds and the signature check is meaningful.

After the attacker's crafted request: an unprivileged network client can POST a synthetic webhook body (no GitHub cryptographic material required) that sets:
- `organization.login` = the login of any org configured in `Shipit.github` that has **no `webhook_secret`** (a legitimate, documented configuration — see `config/secrets.development.shopify.yml`, where `webhook_secret:` is commented as `# nil`), and
- omits `repository.owner.login` (or sets it to the same no-secret org's name), while
- `repository.full_name` = `victim-org/private-repo` (any repository already tracked as a Shipit stack, potentially under a *different*, secret-protected organization).

`verify_signature` resolves `github_app` for the no-secret org, and since `webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the actual `X-Hub-Signature` header (or with no header at all). The request passes verification even though it never carried a valid signature for the organization/repository it actually targets.

`Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }` then runs `PushHandler`, which looks up stacks for `victim-org/private-repo` via `repository_name` (from `repository.full_name`) and calls `stack.sync_github(expected_head_sha: params.after)`, enqueuing `GithubSyncJob` for that stack — a stack whose true owning organization was never authenticated at all. [7](#0-6) 

### Impact

This lets an unauthenticated attacker force Shipit to believe an unsigned/forged push event originated from GitHub for an arbitrary tracked stack, as long as *any* configured organization in the multi-org `Shipit.github` config lacks a `webhook_secret`. This can:
- force spurious `GithubSyncJob` runs (hitting the real GitHub API with the app's credentials, `stack.github_api`) for a stack belonging to a different, secret-protected organization,
- pollute commit history / CI status views, and, combined with continuous deployment enabled on that stack, influence what gets auto-deployed — an unauthorized-deploy-adjacent effect, since `sync_github`/CD logic downstream treats these commits as legitimately observed on GitHub.

This matches the rules' explicit "organization that authenticated versus the repository that is written" binding-break category, and the root cause is provable directly from `WebhooksController#verify_signature` + `GithubApp#verify_webhook_signature` + `Handler#repository_name` diverging on which payload field they trust.

One caveat I could not fully verify within the index: whether a typical production Shipit deployment realistically runs multiple GitHub orgs where one has a blank `webhook_secret` (the single-secret path always requires a valid signature, closing this hole for single-org deployments). The multi-org secrets file in the repo (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) explicitly shows this as a supported, documented configuration shape, which is why I consider the precondition in-scope and not merely theoretical.

### Title
Webhook Signature Verification Uses a Different Organization Field Than the One Used to Select the Target Repository, Allowing Unsigned Cross-Organization Push Events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify a webhook's signature using `repository_owner`, derived from `repository.owner.login` **or** the unrelated top-level `organization.login` field. Webhook `Handler`s (e.g. `PushHandler`) instead resolve the actual target stack from `repository.full_name`. When any configured organization has no `webhook_secret` (a supported configuration), signature verification is unconditionally skipped for requests claiming that organization via the `organization` key, while the handler still processes an attacker-controlled `repository.full_name` pointing at a different, real, secret-protected stack.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
`repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')` — an unverified body field, checked before any signature verification occurs. [8](#0-7) 

`GithubApp#verify_webhook_signature` short-circuits to `true` when the resolved org has no `webhook_secret`: [3](#0-2) 

Meanwhile every handler (`Handler#stacks`/`#repository_name`) uses `payload.dig('repository', 'full_name')` — a different field entirely — to look up the actual `Repository`/`Stack` records to act on: [4](#0-3) 

There is no requirement anywhere that `repository.full_name`'s owner match `repository_owner`/`organization.login`. An attacker can therefore decouple "the org whose (absent) secret is checked" from "the repository whose stacks get processed."

### Impact Explanation
Falls under High: "unauthenticated read of stack state / an unauthorized deploy [-adjacent]" — an attacker can trigger `GithubSyncJob` (which calls the real GitHub API via `stack.github_api` and appends commits) for any tracked stack without a valid signature, as soon as one configured org has a blank `webhook_secret`. This can seed forged commit/head state that downstream continuous-deployment logic acts on.

### Likelihood Explanation
Requires a specific but documented and supported precondition — a multi-org Shipit deployment where at least one configured organization has no `webhook_secret` set (shown as valid in-repo configuration in `config/secrets.development.shopify.yml` / `test/dummy/config/secrets_double_github_app.yml`). Given that precondition, the attack requires only an unauthenticated HTTP POST with a crafted JSON body and the correct `X-Github-Event` header — no credentials, tokens, or GitHub App secrets needed.

### Recommendation
Verify the webhook signature using the secret associated with the **same** organization/repository that the handler will actually act on (i.e., derive both from `repository.full_name`'s owner, not from a separate/optional `organization.login` fallback), and disallow signature bypass (`return true unless webhook_secret`) from being reachable via attacker-supplied organization selection — e.g., require every configured organization to have a webhook secret, or reject events where `repository.full_name`'s owner doesn't match the organization whose secret validated the request.

### Proof of Concept
1. Configure Shipit with two organizations in `Shipit.github`: `OrgA` (no `webhook_secret`) and `OrgB` (has a `webhook_secret`), each with stacks.
2. Have a real stack for `OrgB/victim-repo` already tracked.
3. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "organization": { "login": "OrgA" },
  "repository": { "full_name": "OrgB/victim-repo" },
  "ref": "refs/heads/main",
  "after": "deadbeef..."
}
```
No `X-Hub-Signature` header is required to be valid (or can be omitted/garbage).
4. `repository_owner` resolves to `"OrgA"` (via the `organization.login` fallback, since `repository.owner.login` is absent).
5. `Shipit.github(organization: "OrgA")` returns the app configured with no `webhook_secret`; `verify_webhook_signature` returns `true` unconditionally.
6. `PushHandler` processes the payload, resolving `repository_name` to `"OrgB/victim-repo"`, finds its stacks, and calls `stack.sync_github(expected_head_sha: "deadbeef...")`, enqueuing `GithubSyncJob` for a stack the attacker never proved control over or authenticated against.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
