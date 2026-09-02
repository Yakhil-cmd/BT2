### Title
Webhook signature is verified against the payload's `repository.owner.login`, but push processing looks up the stack by `repository.full_name` - allowing an attacker to forge unsigned push events for any tracked stack (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to validate the signature against using `repository_owner`, which is read straight from the untrusted JSON payload (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). [1](#0-0)  Once the signature check passes, `WebhooksController#create` dispatches the *same* raw payload to `Shipit::Webhooks::Handlers::PushHandler`, which resolves the target stacks using a *different* field of the same payload: `repository.full_name`, via `Handler#repository_name` / `Repository.from_github_repo_name`. [2](#0-1) [3](#0-2) 

Because `owner.login` (used for authentication) and `full_name` (used to select what gets written) are two independent, attacker-controlled fields of the same unsigned/untrusted JSON body, an attacker can pick a `repository.owner.login` belonging to an organization for which Shipit has **no `webhook_secret` configured** (the docs describe the webhook secret as "optional" [4](#0-3) ), while setting `repository.full_name` to a repository owned by a *different*, properly-secured organization that Shipit tracks. `GithubApp#verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is blank, regardless of the signature header supplied. [5](#0-4) 

### Finding Description
The trust binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login)` == `repository whose stack state is mutated (repository.full_name)`

Before the attacker's request: for a legitimate push, `repository.owner.login` and the owner segment of `repository.full_name` refer to the same GitHub organization, so the binding trivially holds. This is implicitly relied upon and is exactly what the current fixture payloads assume (`repository.owner.login == "Shopify"` and `repository.full_name == "Shopify/shipit-engine"`). [6](#0-5) 

After the attacker's request: nothing in `verify_signature` or `PushHandler` cross-checks that `owner.login` and the owner segment of `full_name` are consistent. `verify_signature` only uses `repository_owner` to pick the `GithubApp` instance/secret to verify against:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`PushHandler` (via `Handler#stacks`/`#repository_name`) uses an entirely different field to decide which stacks get synced:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

If the organization named in `repository.owner.login` has no `webhook_secret` configured in Shipit's config, `verify_webhook_signature` returns `true` unconditionally:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [5](#0-4) 

So an attacker who knows (or controls) an organization with no configured webhook secret can send a webhook where `repository.owner.login` = that unsecured org, but `repository.full_name` = `SecuredOrg/tracked-repo`, an actual tracked stack belonging to a different, secured organization. The signature check passes trivially (no secret to validate against), yet `PushHandler` resolves `Repository.from_github_repo_name("SecuredOrg/tracked-repo")` and enqueues `Stack#sync_github` for that stack's branches, using the attacker-supplied `after` SHA as the `expected_head_sha`. [7](#0-6)  `GithubSyncJob` then fetches commits from the real GitHub repo via the app's own GitHub API credentials for that stack (`stack.github_api`), so it does not itself fabricate commits — but it does trigger unsolicited, attacker-initiated syncs against a stack whose webhook trust boundary should have required a secret scoped to the *secured* organization, not the unrelated one. [8](#0-7) 

### Impact Explanation
This breaks the equality "organization authenticated == repository written," letting an unprivileged attacker who has no credentials for the secured organization at all trigger stack synchronization/inaccessibility-state changes and initiate deploy-pipeline-relevant events (`GithubSyncJob`, `CacheDeploySpecJob`) against arbitrary tracked repositories, by simply forging a JSON body toward an organization for which the operator never bothered to configure a webhook secret (an explicitly "optional" setting per the setup docs). This is a High-severity authentication-boundary defect: it allows spoofed events on stacks the attacker does not own or control, without a webhook secret, an `ApiClient` token, or any GitHub credential.

### Likelihood Explanation
Likelihood is Medium-High: the webhook secret is explicitly documented as optional, so multi-organization Shipit deployments (or any org whose secret was never set/rotated) are exposed. No authentication, session, or GitHub write access is required — only knowledge of a GitHub org name that Shipit has configured without a `webhook_secret`, plus the target's full repository name, both of which are typically public information.

### Recommendation
`verify_signature` should validate the signature using the `GithubApp` associated with the organization actually referenced by `repository.full_name` (the entity whose state will be mutated), not a separately-controlled `owner.login`/`organization.login` field. At minimum, the controller should reject payloads where `repository.owner.login` does not match the owner segment of `repository.full_name`, and should not treat a missing `webhook_secret` as an automatic pass when the resolved organization differs from the one performing the write.

### Proof of Concept
1. Configure Shipit with two organizations: `UnsecuredOrg` (no `webhook_secret` set) and `SecuredOrg` (has a `webhook_secret`, tracks stack `SecuredOrg/critical-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and any/garbage `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "UnsecuredOrg" },
    "full_name": "SecuredOrg/critical-repo"
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "UnsecuredOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the bogus signature. [5](#0-4) 
4. `create` then dispatches the payload to `PushHandler`, which resolves stacks via `repository.full_name = "SecuredOrg/critical-repo"` and enqueues `Stack#sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the matching branch stack, without ever having validated a signature scoped to `SecuredOrg`. [7](#0-6)

### Citations

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** test/fixtures/payloads/push_master.json (L55-59)
```json
  "repository": {
    "id": 17266426,
    "name": "shipit-engine",
    "full_name": "Shopify/shipit-engine",
    "url": "https://github.com/Shopify/shipit-engine",
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
