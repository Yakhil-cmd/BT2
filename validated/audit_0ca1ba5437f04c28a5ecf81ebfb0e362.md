### Title
Webhook signature verification keyed on `repository.owner.login` while stack resolution is keyed on `repository.full_name` allows cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the attacker-controlled JSON body, while the handler that actually acts on the payload (`Shipit::Webhooks::Handlers::Handler#stacks` / `#repository_name`) resolves the target `Repository`/`Stack` using the unrelated `repository.full_name` field from the same body. Nothing binds these two fields together, so a signature verified as belonging to organization A can be replayed against a payload whose `full_name` points at organization B's repository.

### Finding Description
`verify_signature` in [1](#0-0)  computes `repository_owner` purely from the JSON body (`params.dig('repository','owner','login') || params.dig('organization','login')`), fetches `Shipit.github(organization: repository_owner)`, and verifies the raw body against **that org's** `webhook_secret`.

Separately, every webhook handler resolves the `Stack`(s) to mutate using `payload.dig('repository', 'full_name')`, as seen in `Handler#repository_name`/`#stacks` [2](#0-1) , and then acts on it, e.g. `PushHandler#process` calls `stack.sync_github(...)` for every non-archived stack matching the branch [3](#0-2) , and `StatusHandler#process` writes a CI status for any commit matching `sha` regardless of repository [4](#0-3) .

Because signature validity is decided from `repository.owner.login` but the actual write target is decided from `repository.full_name`, an operator/administrator who legitimately possesses the `webhook_secret` for their own onboarded organization (org A) can craft a request where:
- `repository.owner.login = "orgA"` (so `Shipit.github(organization: "orgA")`'s secret is used and the HMAC computed with that secret over the whole raw body validates), and
- `repository.full_name = "orgB/victim-repo"` (a different, unrelated organization's repository that also has a `Stack` configured on the same Shipit instance).

`verify_webhook_signature` only checks that the raw body's HMAC matches org A's secret; it performs no cross-check that `full_name`'s owner segment equals the org whose secret was used [5](#0-4) . The request therefore passes as "authenticated for org A" but is dispatched to handlers that operate on org B's stack, breaking the equality that should hold: `organization_that_authenticated == organization_owning_the_repository_written`.

Additionally, note that `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is unset for the resolved organization (`return true unless webhook_secret`) [6](#0-5) , which independently widens the same gap: any org configured without a secret grants an unauthenticated attacker full control over `repository.owner.login` (to hit that no-secret org) combined with unconstrained `repository.full_name` (to select any other stack on the instance) — with zero secret knowledge required.

### Impact Explanation
This breaks the organization↔repository trust binding relied upon by the webhook authentication model. An attacker who controls (or has the secret for) one onboarded organization can:
- Force `GithubSyncJob`/`sync_github` on an arbitrary other organization's `Stack` by forging `push` events, which triggers commit backfill, spec cache recompute (`CacheDeploySpecJob`), and — if `continuous_deployment` is enabled on that victim stack — an automatic deploy of a chosen SHA already reachable on the victim's default branch [7](#0-6) .
- Inject arbitrary CI `status` records for any commit across the whole instance via `StatusHandler`, since it filters only by `sha` with no repository scoping at all [4](#0-3) , which can be used to fabricate green CI so a merge-request/continuous-deployment gate is satisfied on an unrelated stack.

These are cross-repository writes and can culminate in an unauthorized deploy on a stack the attacker does not own — matching the Critical impact bucket (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
Requires only that the attacker be a legitimate administrator (or has learned the webhook secret) of any single organization already onboarded to the same Shipit instance — not privileged access to the victim's org, not a Shipit `ApiClient` token, and not GitHub App private key material. On instances with multiple `github:` orgs configured (the engine explicitly supports and documents this via `config/secrets.yml`'s per-organization `github:` map, see `test/dummy/config/secrets_double_github_app.yml`), this is directly reachable. It is further trivially reachable with no secret at all whenever any configured organization omits `webhook_secret` (a documented, valid configuration per `config/secrets.development.example.yml`).

### Recommendation
Bind signature verification to the same field used for stack/repository resolution: derive the verifying organization from `repository.full_name`'s owner segment (or explicitly reject payloads where `repository.owner.login` and the owner segment of `repository.full_name` differ) before selecting `Shipit.github(organization: ...)`. Also remove or gate the `return true unless webhook_secret` fallback so that a missing secret does not silently disable verification.

### Proof of Concept
1. Shipit instance configured with two organizations, `orgA` (attacker-administered, secret known: `s3cretA`) and `orgB` (victim, has a `Stack` for `orgB/victim-repo`).
2. Attacker crafts JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<sha already on orgB/victim-repo>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(s3cretA, body)>` and POSTs to `/github/webhooks` (mounted webhooks endpoint) with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner == "orgA"`, fetches `orgA`'s `GitHubApp`, and the HMAC validates → request is accepted (`head(:ok)` path, no 422).
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` via `payload.dig('repository','full_name') == "orgB/victim-repo"` and calls `sync_github` on `orgB`'s stack — a write performed on org B despite the request being authenticated only as org A.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
