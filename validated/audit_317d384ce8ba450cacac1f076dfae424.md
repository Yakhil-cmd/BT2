### Title
Webhook signature verification authenticates the wrong organization for the repository actually written to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret used to authenticate an inbound webhook based on `repository_owner`, a value taken from the untrusted JSON payload itself. [1](#0-0)  Every event handler, however, determines which `Stack`/`Repository` to actually mutate using a different field from the same payload: `payload.dig('repository', 'full_name')`. [2](#0-1)  In a multi-tenant deployment (multiple GitHub organizations configured, as documented and tested in `secrets_double_github_app.yml`), these two fields are never cross-checked against each other, so a payload validly signed for one organization can name a repository belonging to a completely different organization.

### Finding Description
The controller resolves the org used for HMAC verification like this:
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
``` [3](#0-2) 

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` when multiple GitHub Apps are configured (`github_app_config(organization)`), and `verify_webhook_signature` performs an HMAC-SHA1 comparison of `request.raw_post` against that org's secret. [4](#0-3) [5](#0-4) 

After `verify_signature` passes, `WebhooksController#create` dispatches the parsed JSON body to the registered handlers for the event type. [6](#0-5)  Handlers such as `PushHandler` never look at `repository_owner` again — they resolve the target `Stack` purely from `payload.dig('repository', 'full_name')`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [7](#0-6) 

`Stack#sync_github` enqueues `GithubSyncJob`, which fetches commits from GitHub and, notably, retries `MAX_RETRY_ATTEMPTS` times if `expected_head_sha` isn't yet visible via the API — accepting the webhook's `expected_head_sha` as an assertion to poll for. [8](#0-7) [9](#0-8) 

**The broken binding, expressed as an equality that fails to hold:**
`organization whose webhook_secret authenticated the request` ≠ `organization that owns the repository/stack actually acted upon`.

Before the attacker's request: for any given inbound webhook, the org identified by `repository.owner.login`/`organization.login` is implicitly assumed (by the code's structure) to be the same org that owns `repository.full_name` — which is always true for genuine GitHub-generated webhooks, since GitHub itself populates both fields consistently for a single event.

After the attacker's crafted request: an attacker who legitimately controls **any** one organization/repository onboarded to this Shipit instance (and therefore holds a valid webhook secret for their own org, delivered to them by GitHub for their own installation) can submit a payload where `repository.owner.login` (or `organization.login`) is their own org — so it passes signature verification — while `repository.full_name` names a **different** org/repo's existing Stack. Because the handler layer only trusts `repository.full_name`, the action executes against a stack the attacker's org has no relationship to.

### Impact Explanation
This is a cross-tenant / cross-repository write: an unprivileged attacker (privileged only within their own onboarded organization) can force `GithubSyncJob` to run against another organization's `Stack`, injecting an arbitrary `expected_head_sha` and triggering commit ingestion/spec re-caching for that victim stack. [9](#0-8)  The same class of forgery applies to the `pull_request` handlers (`opened`, `closed`, `reopened`, `labeled`, `assigned`, etc.), which likewise resolve their target exclusively via `params.repository.full_name`, letting an attacker archive, unarchive, or otherwise manipulate review stacks belonging to a different organization. [10](#0-9) [11](#0-10)  If the victim stack has `continuous_deployment` enabled, forcing ingestion of an attacker-chosen SHA into its commit history can feed directly into automatic deploy triggering, matching the "unauthorized deploy" impact bucket. This satisfies the rules' allowed impact category of cross-repository writes / unauthorized deploy triggered by breaking the "organization that authenticated versus the repository that is written" binding explicitly called out as in-scope.

### Likelihood Explanation
This requires the multi-GitHub-App configuration (`secrets.github` keyed by multiple organizations), which is a documented, supported feature (see `docs/setup.md`, "Using Multiple Github Applications", and the test fixture `test/dummy/config/secrets_double_github_app.yml`). [12](#0-11)  Any operator running Shipit as a shared, multi-tenant service across several GitHub organizations is exposed. The attacker needs no special access to the victim org — only their own legitimate webhook secret, which every onboarded org receives by design; this matches an "unprivileged-attacker" analog relative to the victim repository.

### Recommendation
In `WebhooksController#verify_signature` (or in the shared `Handler` base class), after signature verification succeeds, verify that the organization used to select the webhook secret actually owns the `repository.full_name` referenced by the payload (e.g., look up the target `Stack`/`Repository` and assert its owning organization matches `repository_owner`) before dispatching to handlers. Alternatively, always require the raw signature-selecting field and the field consumed by handlers to be derived from the same, single trusted source and cross-validated.

### Proof of Concept
Preconditions: Shipit is configured with at least two GitHub organizations, `attacker-org` and `victim-org`, each with their own GitHub App/`webhook_secret` (multi-tenant config as in `secrets_double_github_app.yml`). `victim-org/victim-repo` already has an existing `Stack` in Shipit tracking branch `master`.

1. Attacker, who legitimately administers `attacker-org`'s GitHub App, knows `attacker-org`'s `webhook_secret` (delivered to them by GitHub for their own installation).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `repository_owner` resolves to `"attacker-org"`, `Shipit.github(organization: "attacker-org")` returns the attacker-org's `GitHubApp`, and `verify_webhook_signature` succeeds since the signature was computed with that org's secret. [13](#0-12) 
5. `PushHandler#process` runs, resolves `stacks` from `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's existing stack — despite the request never having been authenticated by `victim-org`'s secret. [7](#0-6) [8](#0-7) 

Note: I was unable to inspect `Stack#continuous_deployment` gating and `ContinuousDeliveryJob` end-to-end in this pass to fully trace the path from an injected commit to an actual triggered deploy; if a deeper confirmation of that downstream chain is needed, a full session against `app/jobs/shipit/continuous_delivery_job.rb` and `app/models/shipit/commit.rb` would be required.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
```
