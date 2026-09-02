### Title
Webhook signature verified against `repository.owner.login` while event processing acts on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to HMAC-verify a request against based on `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). [1](#0-0) [2](#0-1)  Once the signature is accepted, the same raw payload is dispatched to handlers that instead resolve the target repository/stack from a *different* field, `payload.dig('repository', 'full_name')`, via `Repository.from_github_repo_name`. [3](#0-2) [4](#0-3)  Nothing ties `repository.owner.login` (the value the signature is checked against) to `repository.full_name` (the value used to pick which stack is acted upon).

### Finding Description
Shipit supports multi-tenant configuration where several independent GitHub organizations are each configured with their own GitHub App and `webhook_secret` under `config/secrets.yml`. [5](#0-4)  `Shipit.github(organization: ...)` looks up the app/secret keyed by organization name, and `GithubApp#verify_webhook_signature` performs a straightforward HMAC compare of the raw request body against that organization's secret. [6](#0-5) 

The binding that should hold is: *the organization whose secret validated the request* == *the repository whose stack is mutated by the event*. Instead:
- `verify_signature` picks the secret using `repository_owner` = `params.dig('repository', 'owner', 'login')`. [2](#0-1) 
- The `push` handler (and other handlers) locate the target `Repository`/`Stack` using `payload.dig('repository', 'full_name')` via `Handler#repository_name`/`Handler#stacks`. [3](#0-2) 

Because `repository.owner.login` and `repository.full_name` are two independent JSON fields inside the same attacker-controlled request body, an entity that legitimately owns one tenant's GitHub App (and therefore its `webhook_secret`, which is generated and known by whoever configures that org's app per the setup docs) can craft a payload where `repository.owner.login` = their own org (so the HMAC check passes using their own secret) but `repository.full_name` = `"victim-org/victim-repo"` (a repository belonging to a different tenant on the same Shipit instance). `PushHandler#process` then calls `stack.sync_github(expected_head_sha:)` on the victim's stack, enqueuing `GithubSyncJob` against the victim repository/stack using the attacker-chosen `after` SHA, all validated only by the attacker's own organization credentials. [7](#0-6) [8](#0-7) 

This is the same class of "identifier mixup" as CVE-2021-22926: one identifier (`repository.owner.login`) is used to select/verify a trust anchor while a different, unchecked identifier (`repository.full_name`) is used to select the object actually acted upon.

### Impact Explanation
A tenant that legitimately controls one GitHub App/organization on a shared Shipit install can forge cross-tenant webhook events (`push`, `status`, `check_suite`, etc., since all handlers use the same `full_name`-based repository resolution) that are accepted as authentic because they satisfy the signature check for their own organization. This can trigger `GithubSyncJob` (and downstream commit ingestion, deploy-spec caching, or CI status writes) against a repository/stack the attacker does not own, without ever needing the victim's webhook secret, `api_clients_secret`, or session — a cross-tenant, unauthorized write against another repository's state.

### Likelihood Explanation
Exploitability depends entirely on a multi-organization Shipit deployment where more than one, mutually-untrusted GitHub organization/tenant is configured (as explicitly documented as a supported setup). [5](#0-4)  In that documented configuration, any tenant admin who can configure/knows their own org's `webhook_secret` can perform this attack with a single crafted POST to `/webhooks`; no privileged Shipit account, session, or victim secret is required.

### Recommendation
After signature verification, re-derive the repository owner from `payload.dig('repository', 'full_name')` (or `organization.login` for org-scoped events) and reject the request (422) if it does not match `repository_owner` used to select the verifying GitHub App/secret. Alternatively, have `verify_signature` iterate/verify against the specific app tied to the resolved `Repository` record rather than trusting an unvalidated payload field to select the verification key.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-app setup).
2. Attacker, knowing `attacker-org`'s webhook secret (as the admin who configured that app), crafts a JSON push payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s app, and the HMAC check succeeds. [1](#0-0) 
5. `PushHandler` resolves the target stacks via `full_name = "victim-org/victim-repo"` and calls `sync_github` on `victim-org`'s stack, enqueuing `GithubSyncJob` against a repository the attacker does not control. [7](#0-6)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
