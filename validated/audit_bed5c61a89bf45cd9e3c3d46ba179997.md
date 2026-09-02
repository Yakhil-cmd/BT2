### Title
Cross-tenant push forgery via mismatched signature-owner and payload full_name - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The `webhook_secret` used to verify the request signature is selected from `repository.owner.login`, while the stack/repository actually mutated by `PushHandler#process` is resolved from an entirely independent field, `repository.full_name`. Since the attacker fully controls the raw JSON body they sign, these two fields can be made to point at different organizations, letting an attacker who owns a legitimate org on the instance forge a push event against any other tenant's stack.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:

`organization_used_for_signature_verification (params.dig('repository','owner','login'))` == `organization_owning_the_mutated_stack (Repository.from_github_repo_name(params.dig('repository','full_name')).owner)`

Path:
1. `WebhooksController#verify_signature` selects the GitHub App/secret by `repository_owner`, defined as `params.dig('repository', 'owner', 'login')`, and validates `X-Hub-Signature` against `request.raw_post` using that org's `webhook_secret`: [1](#0-0)  and [2](#0-1) .
2. Once verification succeeds, `create` parses the same raw body into `params` and dispatches it to handlers unmodified: [3](#0-2) .
3. `Handler#stacks`/`#repository_name` resolve the target repository/stacks from a **different** JSON field, `payload.dig('repository', 'full_name')`, with no reference to `owner.login` at all: [4](#0-3) .
4. `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every not-archived stack tracking the pushed branch of that repository: [5](#0-4) .
5. `Repository.from_github_repo_name` does a straightforward `find_by(owner:, name:)` lookup with no cross-check against any "verified organization" value: [6](#0-5) .

Because the attacker constructs the raw HTTP body themselves (this is not a GitHub-relayed signed event, it's a direct POST to `/webhooks` from any internet client), they can set `repository.owner.login = "attacker-org"` (used only for signature-key selection) and `repository.full_name = "victim-org/victim-repo"` (used only for the actual mutation) in the same payload, then HMAC-sign the exact raw bytes with their own real `attacker-org` `webhook_secret`. `verify_webhook_signature` in `lib/shipit/github_app.rb` only checks the HMAC against the bytes and the secret for the org named in `owner.login` — it has no knowledge of, and does not check, `full_name`: [7](#0-6) . Nothing downstream re-derives or validates that `full_name`'s owner matches `repository_owner`.

This lets the attacker enqueue `stack.sync_github(expected_head_sha: <attacker-chosen sha>)` against `victim-org/victim-repo`'s stack tracking `master`, which triggers `GithubSyncJob` to fetch commits up to that SHA and, combined with `continuous_deployment`/auto-deploy configuration, drive an unauthorized deploy toward attacker-controlled state: [8](#0-7) .

None of the listed guards catch this: `verify_signature` succeeds (attacker's own secret, correctly computed); `drop_unhandled_event` doesn't apply (push is a handled event); `ExplicitParameters` schema for `PushHandler` only requires `ref`/`after` types, not repository ownership consistency: [9](#0-8) ; there is no model validation tying `Repository#owner` to any "verified webhook org" concept.

### Impact Explanation
A payload naming `attacker-org` for signature purposes mutates a stack belonging to `victim-org` — exactly the "payload for one repository mutating another's stack" Critical category. The attacker can repeatedly and arbitrarily choose `expected_head_sha` and target branch for any stack on the instance whose repository owner/name they can guess or discover (repo names/owners are often public knowledge), triggering `GithubSyncJob` and, if continuous deployment is enabled, unauthorized deploys. This is a full cross-tenant authentication-bypass on the webhook boundary for any multi-tenant Shipit instance (one hosting more than one GitHub org's App config), regardless of how many other orgs are configured.

### Likelihood Explanation
Preconditions are minimal and entirely attacker-controllable: the attacker needs (a) to own/administer one legitimate org configured on the shared Shipit instance (so they legitimately know that org's real `webhook_secret`), and (b) knowledge of the victim's `owner/repo` full name (public information for public repos). No victim secrets, sessions, or privileges are required. The forgery is a single scripted POST with a correctly computed HMAC-SHA1 over attacker-chosen bytes — trivial and fully repeatable against any repository/stack combination hosted on the instance.

### Recommendation
Bind the mutated repository to the verified organization: after `verify_signature` succeeds, pass the verified `repository_owner` through to the handler dispatch and have `Handler#stacks`/`#repository_name` (or `PushHandler#process`) reject/ignore events where `payload.dig('repository','full_name').split('/').first` does not case-insensitively equal the `repository_owner` used to select the signing secret. Alternatively, derive the target repository owner from the same field used for signature verification rather than trusting `full_name` independently.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/push_handler_test.rb`):
1. Configure two orgs in test secrets: `attacker-org` with a known `webhook_secret_attacker`, and `victim-org` (or reuse an existing fixture org) with `webhook_secret_victim`.
2. Create `shipit_stacks(:victim)` under `Repository` with `owner: "victim-org", name: "victim-repo"`, `branch: "master"`, continuous deployment enabled.
3. Build `body = { ref: "refs/heads/master", after: "<attacker_sha>", repository: { owner: { login: "attacker-org" }, full_name: "victim-org/victim-repo" } }.to_json`.
4. Compute `signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', webhook_secret_attacker, body)`.
5. Assert the equality-before check: `repository_owner_for_signature = "attacker-org"` vs `repository_full_name_owner = "victim-org"` — they differ.
6. `post :create, body:, as: :json`, with `X-Github-Event: push` and `X-Hub-Signature: signature`.
7. Assert `response.status == 200` (signature accepted) and assert `Shipit::GithubSyncJob` enqueued (or `stack.expects(:sync_github).with(expected_head_sha: "<attacker_sha>")`) for `shipit_stacks(:victim).id`, proving the attacker-org signature authorized a mutation on the victim-org stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-10)
```ruby
        params do
          requires :ref
          requires :after
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
