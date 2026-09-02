Confirmed vulnerability: the webhook signature verification is keyed off `repository.owner.login` (or `organization.login`) extracted from the payload, but the handler that acts on the payload looks up the target `Stack` using `repository.full_name` — a **different field of the same, single signed payload, but not the field the verification decision is bound to as an organization identity**. Because a GitHub App/organization owner only needs to know their own `webhook_secret` (an unprivileged party who legitimately owns *some* org configured in `Shipit.github`), they can produce a validly-signed request whose `repository.full_name` names a victim's repository in a different organization.

### Title
Webhook signature is verified against the owner in the payload while the repository acted upon is taken from a different, unbound payload field, allowing cross-organization stack sync spoofing - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` resolves which GitHub App/organization's `webhook_secret` to use for HMAC verification from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), then verifies the raw body against that organization's secret. [1](#0-0)  If the signature checks out, the whole payload is handed to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` unmodified. [2](#0-1)  Handlers such as `PushHandler` however resolve the target `Stack`/`Repository` via `payload.dig('repository', 'full_name')`, a completely independent field of the same payload. [3](#0-2)  `Repository.from_github_repo_name` simply splits that string on `/` and looks up any repository record by owner/name, with no check that this owner matches the organization whose secret validated the signature. [4](#0-3) 

### Finding Description
The equality that should hold is: `signing_organization == acted_upon_repository.owner`. Instead the engine enforces only `signing_organization == payload["repository"]["owner"]["login"]`, while the repository actually acted upon is `payload["repository"]["full_name"].split('/').first`. These are two independently attacker-controlled strings within one JSON body — nothing forces them to refer to the same repository/organization.

Concretely: `Shipit.github(organization: repository_owner)` is looked up from `repository.owner.login`, and `verify_webhook_signature` only checks that the HMAC-SHA1 of the raw body matches under that organization's `webhook_secret`. [5](#0-4)  An attacker who legitimately administers their own GitHub organization/App configured in Shipit (and therefore knows/controls that org's `webhook_secret`, e.g. by triggering webhooks from their own repo) can freely construct the JSON body themselves (this is a raw HTTP POST to Shipit's public `/github/webhooks` endpoint, not something GitHub validates) so that:
- `repository.owner.login` = `attacker-org` (used only for the signature check, matches the secret used to sign)
- `repository.full_name` = `victim-org/victim-repo`

The signature validates because it's computed with `attacker-org`'s real secret. `PushHandler#process` then resolves `stacks` for `victim-org/victim-repo` [6](#0-5)  and, for each not-archived stack on the matching `branch`, calls `stack.sync_github(expected_head_sha: params.after)`, which is delivered to `GithubSyncJob`. [7](#0-6)  `GithubSyncJob#perform` then fetches commits for that victim stack using `stack.github_commits` — the Shipit App's own GitHub credentials for `victim-org` (not the attacker's) — and appends whatever commits it finds up to `expected_head_sha`, an attacker-supplied SHA, into the victim stack's commit history, then triggers `CacheDeploySpecJob`. [8](#0-7)  If continuous deployment is enabled on the victim stack, appending/forcing sync toward an attacker-chosen `expected_head_sha` can drive an unauthorized deploy of a commit the attacker selects (any commit that legitimately exists in the victim's GitHub history, since Shipit fetches via its own trusted GitHub API access, but the attacker picks *which* SHA/branch position to sync to and forces the retraversal), without ever needing credentials for `victim-org`.

### Impact Explanation
This breaks the binding between "the organization whose secret authenticated this webhook" and "the repository state Shipit will mutate," letting a user who administers an unrelated, Shipit-configured organization forge pushes against a victim stack they have no authorization over, triggering unauthorized commit ingestion and downstream deploy scheduling (`CacheDeploySpecJob`, and continuous delivery deploys) for that victim stack — an unauthorized deploy/rollback-adjacent action performed with the app's own GitHub credentials against a repository the attacker does not control.

### Likelihood Explanation
Likelihood is Medium: it requires the attacker to control (or have webhook_secret knowledge of) at least one organization already configured in the same Shipit instance's `Shipit.github` multi-org configuration — a realistic scenario for any Shipit deployment serving multiple organizations/teams, since onboarding a new org is a normal, low-privilege administrative action, not privileged access to the victim org.

### Recommendation
Bind the signature check to the same field used for stack resolution: derive `repository_owner`/the org used to select the webhook secret from the identical `full_name` (or repository `id`) that `Handler#repository_name` uses, and reject payloads where `repository.owner.login` doesn't match `repository.full_name`'s owner segment. More robustly, resolve the target `Repository`/`Stack` first from the trusted, previously-registered GitHub repository `id` (not attacker-suppliable strings) and confirm the same organization was used both to fetch the webhook secret and to look up the repository, rejecting on mismatch.

### Proof of Concept
1. Attacker onboards/administers `attacker-org`, configured in Shipit's `github:` config with a known `webhook_secret`.
2. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-victim-sha>",
  "repository": {
     "owner": { "login": "attacker-org" },
     "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker signs this exact raw body with `attacker-org`'s `webhook_secret` and sets `X-Hub-Signature` accordingly.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and verifies successfully. [9](#0-8) 
5. `PushHandler#process` resolves stacks for `victim-org/victim-repo` via `Repository.from_github_repo_name` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-victim-sha>")` on them. [7](#0-6) 
6. `GithubSyncJob` runs with the Shipit app's real `victim-org` GitHub credentials, appending commits/kicking off `CacheDeploySpecJob`/continuous delivery on the victim's stack — none of which the attacker was authorized to trigger.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
