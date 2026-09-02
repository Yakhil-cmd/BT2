### Title
Cross-organization webhook confusion in `WebhooksController#verify_signature` allows an unauthorized deploy on another organization's stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to validate a webhook signature with based on `repository.owner.login` (or `organization.login`) taken from the same JSON body being verified, then hands the *entire* parsed body to the event handlers, which independently derive the target repository from `repository.full_name`. Because nothing binds `repository.owner.login` to `repository.full_name`, a party who holds the webhook secret for one configured GitHub organization can sign a payload whose `owner.login` matches their own org (to pass signature verification) while `full_name` points at a repository belonging to a different organization tracked by the same Shipit deployment. This breaks the equality "organization that authenticated == organization whose repository is written," letting the caller drive `push`/`status`/`check_suite` handling for a stack outside the org they authenticated as, up to enqueuing an unauthorized sync and (via continuous delivery) a deploy.

### Finding Description
`verify_signature` picks the `GitHubApp` (and its `webhook_secret`) using only the organization named inside the payload: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

`repository_owner` is read straight from the untrusted body: [2](#0-1) 

Once the signature check passes, the *whole* parsed body is forwarded unmodified to every registered handler for the event: [3](#0-2) 

All the default handlers (push, status via commit lookup, pull_request, check_suite) resolve the actual repository/stack to act on from `repository.full_name`, a *different* field of the same body: [4](#0-3) [5](#0-4) 

`Shipit.github_app_config`/`Shipit#github` supports one `GitHubApp`/webhook secret per organization in the multi-org configuration documented for this engine: [6](#0-5) [7](#0-6) 

Nothing in `verify_webhook_signature` or the handlers cross-checks that `repository.owner.login` (used to pick the secret) matches the owner encoded in `repository.full_name` (used to pick the stack). `verify_webhook_signature` itself only proves the raw body was HMAC-signed with *some* org's secret — it says nothing about which org's repository the body claims to target: [8](#0-7) 

So for a deployment tracking multiple organizations, an attacker who is the legitimate GitHub App owner/administrator for OrgA (and therefore knows/controls OrgA's `webhook_secret`) can POST to `/webhooks` a body such as:
```json
{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"}, "ref": "refs/heads/master", "after": "<attacker-chosen sha>"}
```
signed with `HMAC-SHA1(OrgA_webhook_secret, raw_body)`. `repository_owner` resolves to `"OrgA"`, the signature check succeeds against OrgA's app, but `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` — a stack belonging to OrgB, an organization the attacker never authenticated as.

### Impact Explanation
This is an unauthorized cross-organization write: the forged push causes `stack.sync_github(expected_head_sha: ...)` to run for OrgB's stack, which enqueues `GithubSyncJob` to fetch and append attacker-influenced commits into OrgB's stack history: [9](#0-8) [10](#0-9) 

Because `sync_github_if_necessary`/appended commits can drive Shipit's continuous-delivery pipeline for stacks with CD enabled, this can result in an unauthorized deploy being scheduled for a repository/organization the requester never had credentials for — matching the Critical "unauthorized deploy" category. Even without CD enabled, it lets an outside org's webhook holder forge `status`/`check_suite` state (commit statuses, merge-readiness signals) for a target org's commits, which can unblock or trigger merges/deploys gated on that status.

### Likelihood Explanation
Requires only that the Shipit instance is configured with the documented multi-organization GitHub App setup (`config/secrets.yml` keyed per organization) and that the attacker is the legitimate holder of a webhook secret for *any one* of the tracked organizations — not a Shipit account, `ApiClient` token, or `GITHUB_TOKEN`. No collusion with Shipit operators or the victim org is required; the mismatch between the field used for secret selection and the field used for repository selection is unconditional in the code path.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after resolving the signing organization, validate that every repository-bearing sub-object in the payload (`repository.full_name`'s owner segment, `organization.login`, etc.) is consistent with `repository_owner`, and reject (422) on mismatch. Alternatively, have each `Handler` resolve the stack via the same organization used to select the signing secret rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section), each with at least one tracked stack.
2. As the holder of `OrgA`'s webhook secret, craft a `push` event JSON body with `repository.owner.login = "OrgA"` and `repository.full_name = "OrgB/<OrgB's tracked repo>"`, `ref = "refs/heads/<OrgB stack branch>"`, `after = "<attacker-chosen sha>"`.
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POST to `/webhooks` with header `X-Github-Event: push`.
4. Observe `verify_signature` succeeds (secret matches `OrgA`), then `PushHandler` looks up stacks for `OrgB/<repo>` and enqueues `GithubSyncJob`/`Stack#sync_github` for OrgB's stack, confirming a cross-organization action was taken using only OrgA's credentials.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
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
