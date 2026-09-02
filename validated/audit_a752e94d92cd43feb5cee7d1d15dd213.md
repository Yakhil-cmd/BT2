### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but stack lookup and mutation use the independent `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read directly out of the untrusted JSON payload. The rest of the request pipeline (`Handler#stacks`) independently derives the target repository from a different, also attacker-controlled, payload field (`repository.full_name`). These two fields are never cross-checked, so a valid signature for organization A does not guarantee the payload actually concerns organization A's repository.

### Finding Description
`verify_signature` computes the verifying organization purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `webhook_secret` configured for that org in `secrets.yml` (Shipit explicitly supports multiple orgs/GitHub Apps per install, each with its own `webhook_secret`, per `docs/setup.md` and `config/secrets.development.shopify.yml`). The signature is a plain HMAC over the raw body using that org's secret: [3](#0-2) 

Once the signature is accepted, `create` hands the *entire* JSON payload to the event handlers unchanged: [4](#0-3) 

Every handler (e.g. `PushHandler`, `StatusHandler`, `CheckSuiteHandler`) resolves the target stacks from a *different* payload field, `repository.full_name`, with no relation to the field used for signature verification: [5](#0-4) [6](#0-5) [7](#0-6) 

**Binding broken:** *organization authenticated* (`repository.owner.login` used to pick the HMAC secret) ≠ *repository written* (`repository.full_name` used to select the `Stack`/`Repository` actually mutated).

An attacker who legitimately administers **any** organization/GitHub App configured in a multi-tenant Shipit instance (a normal, supported deployment shape shown in `docs/setup.md`, where multiple unrelated orgs each install their own GitHub App and receive their own `webhook_secret`) knows that organization's `webhook_secret`. They can craft an arbitrary JSON body with `repository.owner.login` set to their own org (so the signature check passes using a secret they legitimately possess) while setting `repository.full_name` to point at a completely different, victim organization's tracked repository. Because the signature only authenticates "this body came from someone who knows Org-A's secret," not "this body only concerns Org-A's repositories," the forged event is accepted and dispatched with full effect against the victim's stack.

For the `push` event this reaches `PushHandler#process`, which queues `stack.sync_github(expected_head_sha:)` for every stack in the victim repository matching the pushed branch: [7](#0-6) 
which triggers `GithubSyncJob`, fetching real commit history via the app's actual GitHub credentials for the victim org and appending new commits: [8](#0-7) 
For stacks with `continuous_deployment` enabled, newly appended commits trigger an automatic deploy (`Commit#create_from_github!` continuous-deployment logic in `app/models/shipit/commit.rb`), meaning an attacker with no privileges on the victim org can force an unscheduled sync/deploy cycle on it merely by forging a `push`/`status`/`check_suite` webhook whose signature is valid for a wholly unrelated org they control.

### Impact Explanation
This crosses a real trust boundary without any privileged Shipit credential, GitHub App private key, or repository access on the victim org — only knowledge of a *different* org's webhook secret (attacker's own, legitimate) is required. The forged event lets an unprivileged outsider force `GithubSyncJob` (and, for continuous-deployment stacks, an unauthorized deploy) against any organization/repository tracked by the same multi-tenant Shipit instance. This matches the "unauthorized deploy" / cross-repository write class explicitly called out as Critical impact.

### Likelihood Explanation
Any customer/tenant who is allowed to register their own GitHub App + webhook secret with a shared Shipit instance (the documented multi-org configuration) can exploit this without further access. No timing race, no secret guessing, and no rate limiting is needed — a single crafted POST to `/webhooks` suffices.

### Recommendation
`verify_signature` should not select the verification secret from attacker-controlled payload content used later for repository resolution without binding the two together. At minimum: after resolving `Repository.from_github_repo_name(repository.full_name)`, verify that `repository.owner` (from that resolved `Repository` record) equals the `repository_owner` value used to select the GitHub App/secret, rejecting the webhook if they diverge. More robust: identify the GitHub App/organization the webhook was signed for independent of body content (e.g. via the URL path/organization-scoped webhook endpoint) rather than trusting `repository.owner.login` or `organization.login` fields inside the JSON body itself.

### Proof of Concept
1. Attacker legitimately registers "AttackerOrg" as a GitHub App integration on the shared Shipit instance and knows `webhook_secret_AttackerOrg`.
2. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<any-real-sha-of-victim-repo>",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(webhook_secret_AttackerOrg, body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "AttackerOrg")` and validates successfully because the attacker legitimately knows that secret — see [1](#0-0) .
5. `create` dispatches the full payload to `PushHandler`, which resolves stacks via `repository.full_name = "VictimOrg/victim-repo"` — see [5](#0-4)  — and enqueues `GithubSyncJob` for `VictimOrg`'s stack, despite the signature never having been verified against `VictimOrg`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
