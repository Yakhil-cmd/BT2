### Title
Webhook signature verification authenticates the wrong organization, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a request against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). However, every event handler (`PushHandler`, the `PullRequest::*` handlers, etc.) determines which repository/stack to act on using a *different* field: `params.dig('repository', 'full_name')`. Because these two fields are never cross-checked against each other, and neither is bound together by the HMAC signature computation in a way that ties "owner used to pick the secret" to "repo actually acted upon," an attacker who controls a legitimately configured organization's webhook secret can forge a validly-signed webhook whose `repository.owner.login` names their own org (to pass verification) while `repository.full_name` names a victim repository belonging to a different organization onboarded to the same Shipit instance.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` (lines 24-49) computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` (lines 59-62) is:
```ruby
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
``` [1](#0-0) [2](#0-1) 

`Shipit.github` resolves per-organization configuration (and thus per-organization `webhook_secret`) in multi-org setups via `github_app_config(organization)`, keyed strictly by the organization name passed in: [3](#0-2) 

`GitHubApp#verify_webhook_signature` performs a straightforward HMAC-SHA1 comparison of the signature against `request.raw_post` using that organization's own `webhook_secret` — it never checks that the secret used belongs to the repository that will actually be processed: [4](#0-3) 

Once the signature check passes, `WebhooksController#create` dispatches the entire raw JSON body to handlers: [5](#0-4) 

But the handlers resolve the target repository/stack from `payload.dig('repository', 'full_name')`, an entirely separate JSON field from `repository.owner.login`:
- Base `Handler#repository_name`: [6](#0-5) 
- `PushHandler#process`, which triggers `stack.sync_github(expected_head_sha: params.after)`: [7](#0-6) 
- Pull-request handlers resolving repository via `params.repository.full_name` independently of any owner check, and acting on review stacks (`archive!`, `unarchive!`, `find_or_create!`): [8](#0-7) [9](#0-8) 

`Repository.from_github_repo_name` does a straight lookup by owner/name parsed out of `full_name` with no relation back to the org whose secret validated the request: [10](#0-9) 

**The broken binding, stated as an equality that the code assumes but never enforces:**
`organization used to select/verify the webhook secret (repository.owner.login)` **==** `organization of the repository the handlers actually operate on (repository.full_name)`

This equality holds for genuine GitHub webhooks (GitHub always sets both fields consistently for a single delivered event), but nothing in Shipit's own code enforces it — an attacker fully controls the JSON body and only needs to know one org's own `webhook_secret` (which they legitimately possess, e.g., because they administer that org's GitHub App) to sign a payload that lies about `repository.full_name`.

### Impact Explanation
This is a cross-repository/cross-organization write primitive available to anyone who controls the webhook secret for any one organization configured on the shared Shipit instance (the documented multi-org config schema, `secrets.github.<org>.webhook_secret`, is explicitly supported per `lib/shipit.rb#github_app_config` and `docs/setup.md`/example secrets files). Such an attacker (unprivileged with respect to other organizations' Shipit stacks) can forge:
- `push` events with an attacker-chosen `after` SHA against a victim stack in another org, forcing `GithubSyncJob` to sync/import that head, which mutates commit state (`stack.commits.create_from_github!`) and can cascade into `CacheDeploySpecJob` and downstream deploy pipeline behavior for the victim stack. [11](#0-10) 
- `pull_request` events (opened/closed/reopened/labeled/unlabeled) causing creation, archival, or unarchival of victim review stacks belonging to a repository outside the attacker's own organization. [12](#0-11) [13](#0-12) 

This is a cross-repository write via authentication-bypass of the organizational trust boundary the signature check is meant to enforce, satisfying the Critical "cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Requires the Shipit instance to be configured for multiple GitHub organizations (the supported multi-tenant config schema) and requires the attacker to already control (as an org owner/administrator) the webhook secret for at least one onboarded organization — a bar lower than compromising the victim organization, and explicitly an "unprivileged" position relative to the victim org's stacks. No GitHub App private key, `GITHUB_TOKEN`, Shipit session, or API token is needed; only the ability to `POST /webhooks` with a crafted body signed with a secret the attacker legitimately owns for their own org.

### Recommendation
Bind the signature-verification organization to the same value the handlers use for repository resolution: derive `repository_owner` from `repository.full_name` (split on `/`) rather than `repository.owner.login`/`organization.login`, or, after verification, re-check that `repository.owner.login` (or `full_name`'s owner segment) matches the organization whose secret validated the signature and reject (`head 422`) on mismatch.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md` multi-org schema).
2. Attacker administers `org-a`'s GitHub App and thus knows `org-a`'s `webhook_secret`.
3. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-a-webhook-secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s `GitHubApp`, and the signature verifies successfully against `org-a`'s secret. [1](#0-0) 
6. `create` dispatches to `PushHandler`, which resolves the target via `payload.dig('repository', 'full_name')` = `"org-b/victim-repo"`, and enqueues `GithubSyncJob` against `org-b`'s stack with the attacker-chosen `expected_head_sha`, despite the request never being signed by `org-b`. [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
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
