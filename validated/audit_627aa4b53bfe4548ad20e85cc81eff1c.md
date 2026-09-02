### Title
Webhook signature verified against attacker-controlled organization while payload's `repository.full_name` is trusted to select the victim stack to act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to HMAC-verify the raw webhook body against using `repository_owner`, which is read from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). Once the signature check passes, `create` dispatches the payload to handlers that independently derive the target stack from `payload.dig('repository','full_name')` (see `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`). Nothing enforces that the organization whose secret validated the signature is the same organization that owns the repository the handlers subsequently act on.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
`Shipit.github(organization:)` (in `lib/shipit.rb`) looks up per-organization config (`github_app_config(organization)`), each of which can carry its own `webhook_secret` (`lib/shipit/github_app.rb`, `@webhook_secret = @config[:webhook_secret].presence`). This is the multi-tenant configuration (`Shipit.github_organizations`) that lets one Shipit instance serve several distinct GitHub organizations, each with a separate `webhook_secret`.

Meanwhile, event handlers such as `PushHandler`/`Handler#stacks` resolve which stack to mutate purely from the request body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`repository_owner` (used for signature verification/org selection) and `repository_name` (used for stack selection) are read from two different, independently attacker-suppliable JSON fields of the same raw body: `repository.owner.login` and `repository.full_name`. Since the controller only computes an HMAC over the raw body using the secret belonging to whatever `repository.owner.login` the attacker puts in the payload, an attacker who legitimately knows (or controls) the `webhook_secret` for **one** org configured in this multi-tenant Shipit instance can forge a signature for a payload whose `repository.full_name` targets a completely different organization's repository/stack.

Concretely, a caller with knowledge of Org A's `webhook_secret` can POST:
```json
{
  "repository": {
    "owner": {"login": "org-a"},
    "full_name": "org-b/victim-repo"
  },
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha, or a real sha of a malicious/older commit>"
}
```
with `X-Hub-Signature: sha1=<HMAC over the raw body using Org A's webhook_secret>` and `X-Github-Event: push`. `verify_signature` computes `repository_owner == "org-a"`, fetches Org A's `GithubApp`, verifies the HMAC successfully. `create` then calls `PushHandler.new(params).process`, which resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` — i.e., it performs a genuine sync/deploy-triggering action on Org B's stack, even though the actual signature check never validated anything against Org B's secret.

### Impact Explanation
This breaks the deployment-trust binding: "an organization that authenticated versus the repository that is written." `GithubSyncJob` (queued from `stack.sync_github`) fetches commits and, combined with `continuous_deployment`, can trigger an unauthorized deploy on a victim organization's stack that the attacker's organization has no legitimate relationship to, purely by knowing one org's webhook secret. Depending on which handler is invoked with a crafted `repository.full_name`/`organization.login` combination (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.), this can also be used to manipulate merge-queue state, spoof CI/check-run statuses that gate `continuous_delivery`/`merge_request` merges, or otherwise cause unauthorized state changes on stacks belonging to a repository the attacker's org does not administer — matching the "unauthorized deploy" impact bucket.

### Likelihood Explanation
Exploitability requires the attacker to possess a valid `webhook_secret` for at least one organization configured on the shared Shipit instance (a realistic scenario for any multi-tenant Shipit deployment servicing several orgs/customers, where one tenant is by design a legitimate but unprivileged party with respect to other tenants' repositories). Given that secret, the rest of the attack is a single unauthenticated HTTP POST to `/webhooks` with a hand-crafted body — no repository write access, GitHub App installation, or session is required for the target repository. This satisfies the "unprivileged attacker" and "no target-repo write access" constraints.

### Recommendation
Ensure the organization used to select/verify the webhook signature is the same organization the payload will act on before dispatching to handlers: derive both `repository_owner` and `repository_name` from the *same* `repository` object and additionally verify, after choosing the signing org, that `Repository.from_github_repo_name(repository_name)`'s owner matches `repository_owner` (or simply verify against every configured org's secret and require that the payload's `repository.owner.login` equals the first path segment of `repository.full_name`) before allowing handlers to touch any stack.

### Proof of Concept
1. Configure/obtain the `webhook_secret` for organization `org-a` on a Shipit instance that is multi-tenant (also serving `org-b`).
2. Craft JSON body:
```json
{"repository":{"owner":{"login":"org-a"},"full_name":"org-b/victim-repo"},"ref":"refs/heads/master","after":"<sha>"}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(org-a webhook_secret, body)`.
4. `POST /webhooks` with header `X-Github-Event: push` and the body/signature above.
5. `WebhooksController#verify_signature` passes (verified against `org-a`'s secret). `PushHandler` runs against `org-b/victim-repo`'s stacks via `Repository.from_github_repo_name`, triggering `stack.sync_github`, an action the attacker was never authorized to perform on `org-b`'s repository. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-63)
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
  end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L26-39)
```ruby
        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** lib/shipit/github_app.rb (L44-83)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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
