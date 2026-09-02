### Title
Cross-tenant/cross-repository commit-status forgery via unscoped `StatusHandler` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Shipit's webhook signature verification binds a request's authenticity to the *organization* named inside the payload (`repository.owner.login` / `organization.login`), but the `status` event handler never re-checks that binding against the *repository* it actually mutates. `StatusHandler#process` looks up commits solely `by sha`, with no repository/stack scoping, so a validly-signed webhook from one GitHub organization/App-installation registered in Shipit can flip the CI status of a commit belonging to a completely different tracked repository/organization, which can unblock merges and deploys for a stack the attacker does not control.

### Finding Description
`WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against based on a field read straight out of the untrusted payload: [1](#0-0) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — i.e., the "organization that authenticated" is whatever the payload claims it is, and Shipit looks up that organization's own `webhook_secret` via `Shipit.github(organization:)` / `github_app_config` to verify the signature: [2](#0-1) 

This confirms Shipit explicitly supports multi-organization configuration, each with its own webhook secret — so a signature only proves "this request was signed by organization A's secret," not "this request may only affect data belonging to organization A's repositories."

After verification, `WebhooksController#create` dispatches the raw JSON `params` (not `repository_owner`) to the registered handler for the event: [3](#0-2) 

For `status` events, the handler is: [4](#0-3) 

`Commit.where(sha: params.sha)` performs a **global** lookup with no constraint tying it back to the repository/organization that the signature was actually verified against (unlike, e.g., `PushHandler`/`pull_request` handlers, which scope via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`): [5](#0-4) [6](#0-5) 

Matched commits then have their status updated and, crucially, this can trigger merge/deploy machinery for the owning stack regardless of which organization's secret authenticated the request: [7](#0-6) 

`stack.schedule_merges` enqueues `ProcessMergeRequestsJob`, which can call `merge_request.merge!` once all status checks pass: [8](#0-7) 

**The broken equality:** `organization authenticated by verify_signature` ≠ `repository/stack whose commit status StatusHandler mutates`. The signature only proves the payload was signed by *some* configured org's webhook secret; nothing ties the `sha` being acted on back to that same org's repositories.

### Impact Explanation
A commit SHA is content-addressed and reproducible: if a target's commit content (tree, parents, author/committer identities and timestamps, message) is known — trivial for any commit in a public repository, or a commit an attacker previously collaborated on — an attacker can reproduce the byte-identical commit (same SHA) inside their own repository under their own GitHub organization that they've configured as a Shipit-tracked repo with their own valid webhook secret. They can then generate a genuine, correctly-signed `status` webhook for that SHA from their own repo (e.g., via the GitHub Statuses API on their own commit) and set `state: success`. Because `StatusHandler` matches purely on `sha`, Shipit will apply that success status to the victim's identical-SHA commit in a different, unrelated stack, potentially advancing `stack.schedule_merges` → `ProcessMergeRequestsJob` → `merge_request.merge!`, i.e., an unauthorized/forced merge or deploy progression on a stack the attacker does not own. This satisfies the "unauthorized deploy, rollback, or merge" Critical-impact criterion via a genuine cross-repository write.

### Likelihood Explanation
Requires: (1) Shipit configured for multiple organizations (each maintaining its own webhook secret, a supported and documented configuration per `docs/setup.md` and `lib/shipit.rb`'s `github_organizations`), (2) attacker controls at least one such organization's repo/webhook credentials for their own tenant (not a privileged Shipit account, and not the victim's credentials), and (3) attacker can reproduce a target commit's exact SHA in their own repo. Reproducing an SHA is feasible when the target commit is public (fork+recreate identical git object) or shared via common history/vendoring. This is a moderate-likelihood, high-impact multi-tenant isolation failure — no access to the victim org, the victim's webhook secret, or any Shipit session/token is needed.

### Recommendation
Scope the `status` (and any other sha/ref-keyed) handler lookups to the repository implied by the verified organization, mirroring the pattern already used in `PushHandler`/pull-request handlers (`Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`), and additionally verify that `repository.full_name`'s owner matches the `repository_owner` used to select the verification secret in `WebhooksController#verify_signature`, rejecting payloads where these two disagree.

### Proof of Concept
1. Shipit is configured with two GitHub organizations, `attacker-org` and `victim-org`, each with its own registered webhook secret.
2. Attacker identifies a commit in a `victim-org` repo tracked by Shipit (SHA `abc123...`), e.g. from a public repository history.
3. Attacker recreates a byte-identical git commit object (same tree/parents/author/committer/timestamps/message) inside a repository under `attacker-org`, producing the same SHA `abc123...`.
4. Attacker uses the GitHub Statuses API (their own repo, their own permissions) to post a `success` status for `abc123...` on their `attacker-org` repo, which GitHub delivers as a `status` webhook to Shipit, HMAC-signed with `attacker-org`'s webhook secret.
5. `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org` and successfully verifies the signature using `attacker-org`'s secret.
6. `Shipit::Webhooks::Handlers::StatusHandler#process` executes `Commit.where(sha: 'abc123...')`, matching the `victim-org` commit, and calls `commit.create_status_from_github!(params)`, marking it `success` and potentially triggering `stack.schedule_merges` for the victim's stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-32)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
    end
```
