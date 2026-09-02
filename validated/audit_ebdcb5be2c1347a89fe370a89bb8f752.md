### Title
Cross-tenant webhook confusion: signature verified against `repository.owner.login`'s org secret while stack lookup uses the same request's unchecked `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook by looking up `Shipit.github(organization: repository_owner)` using `params.dig('repository', 'owner', 'login')`, then verifying the HMAC with that organization's `webhook_secret`. Downstream, `Handler#repository_name` (used by `PushHandler#process`) independently reads `payload.dig('repository', 'full_name')` from the very same, attacker-controlled JSON body, with no check that the two values are consistent. Because nothing enforces `full_name`'s owner segment matches `owner.login`, an attacker who administers a legitimate tenant org ("attacker-org") in a multi-org Shipit deployment can sign a JSON body whose `repository.owner.login` is `attacker-org` (so signature verification passes with attacker-org's own secret) but whose `repository.full_name` is `victim-org/victim-repo`, causing `PushHandler` to enqueue `GithubSyncJob` against a stack it does not own.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first`, i.e. that the organization whose secret authenticated the request is the same organization whose repository/stack gets mutated. This is never checked.

- `verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`. [1](#0-0)  The organization key selects a per-tenant `webhook_secret` from `secrets.github` via `Shipit.github_app_config` / `GitHubApp#verify_webhook_signature`. [2](#0-1) [3](#0-2) 
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')` directly from the raw payload (not through `verify_signature`'s `repository_owner`, and not validated by `ExplicitParameters`), and `stacks` resolves `Repository.from_github_repo_name(repository_name)`. [4](#0-3) 
- `PushHandler` only requires `:ref` and `:after` in its param schema — it never requires or validates `repository.owner.login` or `repository.full_name` consistency — and its `process` method finds all non-archived stacks matching branch and calls `stack.sync_github(expected_head_sha: params.after)`. [5](#0-4) 
- `Repository.from_github_repo_name` performs a straightforward lookup with no ownership check against the authenticated organization. [6](#0-5) 

Attacker request: `POST /webhooks` with `X-Github-Event: push`, body `{"ref":"refs/heads/master","after":"<sha>","repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"}}`, and `X-Hub-Signature` computed over the raw body using attacker-org's own `webhook_secret` (which the attacker, as an admin of their own onboarded GitHub org, configured on GitHub's webhook settings page and therefore knows). `verify_signature` resolves `Shipit.github(organization: 'attacker-org')`, verifies successfully, and the request proceeds. `PushHandler` then resolves the stack via `victim-org/victim-repo`'s `full_name` and calls `stack.sync_github`, which triggers `GithubSyncJob` enqueue for the victim's stack. [7](#0-6) 

No existing guard prevents this: `drop_unhandled_event` only checks the event type exists a handler for; `ExplicitParameters` schemas for `PushHandler` don't require or cross-validate `repository`; `Repository` model validations only constrain `owner`/`name` character format, not cross-request consistency; and `verify_signature`'s only check is the HMAC against the org selected by the very same untrusted `owner.login` field that has no relationship enforced with `full_name`.

### Impact Explanation
A push-event webhook authenticated under one tenant's secret (attacker-org) causes `GithubSyncJob` to be enqueued against a stack that belongs to a different tenant (victim-org), which fetches commits from GitHub and appends them into the victim's stack commit history via `stack.commits.create_from_github!` and can trigger `CacheDeploySpecJob`. This is a write for a repository/stack that never authenticated the request that mutated it — a cross-tenant stack-mutation matching the Critical category ("a payload for one repository mutating another's stack"). The attack is repeatable against any stack in the multi-tenant Shipit instance whose `owner/name` (or branch) the attacker can guess or enumerate, as long as the attacker controls at least one onboarded organization's webhook secret.

### Likelihood Explanation
This requires a **multi-organization** Shipit deployment (`Shipit.github_default_organization` non-nil, i.e., `secrets.github` keyed by multiple org names) where the attacker legitimately administers one of the configured GitHub organizations (attacker-org) and therefore knows/controls that org's `webhook_secret` (set when configuring the GitHub webhook on their own org). Given that precondition, the attack costs a single crafted HTTP POST with a valid HMAC computed from a secret the attacker already possesses — no other secrets, sessions, or privileged roles are needed. This is fully repeatable and scriptable against any known `owner/name` target repo present in the shared Shipit instance.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), after verifying the signature, assert that the organization used to resolve the webhook secret matches the owner segment of the repository object that will actually be used by handlers (i.e., compare `repository_owner` against `payload.dig('repository','full_name')&.split('/')&.first`, case-insensitively) and reject (422) on mismatch. Additionally, `Handler#repository_name`/`stacks` should verify that the resolved `Repository#owner` matches the authenticated `repository_owner` before operating on it, rather than trusting `full_name` unconditionally.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "push webhook signed by attacker-org cannot sync victim-org's stack via mismatched owner/full_name" do
  victim_repo = shipit_repositories(:shipit) # owner: victim-org, name: victim-repo (fixture)
  victim_stack = victim_repo.stacks.first

  body = {
    "ref" => "refs/heads/#{victim_stack.branch}",
    "after" => "deadbeefcafefeedfacefeeddeadbeefcafefeed",
    "repository" => {
      "owner" => { "login" => "attacker-org" },
      "full_name" => victim_repo.full_name # "victim-org/victim-repo"
    }
  }.to_json

  Shipit.github(organization: "attacker-org").stubs(:verify_webhook_signature).returns(true)

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = 'sha1=irrelevant-because-stubbed'

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: "deadbeefcafefeedfacefeeddeadbeefcafefeed"]) do
    post :create, body:, as: :json
  end
  # Binding check: repository_owner ('attacker-org') != full_name owner ('victim-org') yet the job still enqueues for victim's stack.
end
```
This demonstrates that `repository_owner` (used for HMAC org selection) and the owner implied by `repository.full_name` (used for stack resolution) diverge while a job is still enqueued for the victim's stack, confirming the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-17)
```ruby
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
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
