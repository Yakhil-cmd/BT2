### Title
Cross-organization forged CI status accepted by `StatusHandler#process` bypasses `MergeRequest#reject_unless_mergeable!` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` for an incoming GitHub `status` webhook with a global, unscoped `Commit.where(sha: params.sha)` lookup, with no constraint tying the commit back to the organization that signed the webhook. Because `WebhooksController#verify_signature` only proves that the payload was signed with the secret configured for *some* organization (chosen by the attacker-controlled `repository_owner` field), an attacker who controls a repository in *any* Shipit-configured organization can forge a `status` event for a `sha` belonging to a victim stack in a *different* organization, injecting a fabricated `success` status that `MergeRequest#all_status_checks_passed?` / `any_status_checks_failed?` will read.

### Finding Description
The broken binding, stated as an equality that must hold but does not:
`Commit#stack.repository.owner == organization_that_signed(webhook)` for every `Commit` row mutated by `StatusHandler#process`.

Code path:
1. `WebhooksController#verify_signature` derives the signing org strictly from attacker-controlled payload fields (`repository_owner`) and validates the signature against that org's own `webhook_secret`: [1](#0-0) . This only proves "signed by someone who knows organization `X`'s secret" — it says nothing about which `Commit`/`stack` the payload's `sha` belongs to.
2. `Shipit.github(organization:)` resolves per-organization config (`secrets.github[org]`), each with its own independent `webhook_secret`: [2](#0-1)  and [3](#0-2) . In a multi-org Shipit deployment, an attacker who legitimately owns/controls a repository in Organization B (one of possibly many configured orgs) knows or can trigger a validly-signed webhook for Org B.
3. `StatusHandler#process` then does a **global**, unscoped commit lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — [4](#0-3) . It never checks that the matched `Commit`'s `stack`/`repository` belongs to Organization B (the org that actually signed the request).
4. `commit.create_status_from_github!` writes a new `Status` row and, via `add_status`, can schedule merges: [5](#0-4) .
5. `MergeRequest#all_status_checks_passed?` / `#any_status_checks_failed?` build a `StatusChecker` directly from `head.statuses_and_check_runs`, which now includes the forged row, with no re-derivation from the actual owning org: [6](#0-5) .
6. `reject_unless_mergeable!` relies on those same predicates to decide whether to reject, and `merge!`/`refresh!` proceed if they pass: [7](#0-6) .

`Commit.by_sha`/`by_sha!` scoped lookups exist elsewhere (e.g. `find_or_create_commit_from_github_by_sha!` uses `stack.commits.by_sha`), showing the codebase already has a pattern for stack-scoped commit resolution that `StatusHandler` does not use: [8](#0-7) , [9](#0-8) .

None of the existing guards close this gap: `verify_signature` authenticates the *sender's org* only, not the *target commit's org*; `drop_unhandled_event`/`ExplicitParameters` (`sha`, `state`, etc.) validate shape, not ownership; there is no `require_permission!`/`stacks` scope check inside webhook handlers since webhooks are inherently unauthenticated-by-session and rely solely on the per-org signature, which this handler fails to bind to the affected row.

### Impact Explanation
A forged, cross-tenant `success` status is written for a victim's `Commit`, potentially causing `all_status_checks_passed?` to return true or `any_status_checks_failed?`/`any_status_checks_missing?` to under-report, so `reject_unless_mergeable!` fails to reject and a pending `MergeRequest` proceeds to `merge!`, invoking `stack.github_api.merge_pull_request` on the victim's real GitHub repository. This is an unauthorized merge triggered by a payload that did not authenticate against the victim's organization — matching the "payload for one repository mutating another's stack/commit" and "unauthorized merge" Critical categories. The attack is repeatable against any `sha` value the attacker can discover (commit SHAs are public for public repos, or can be replicated bit-for-bit via a fork sharing the same git history/commit objects), and against any organization configured in the same Shipit instance, so blast radius spans all tenants sharing the deployment.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured with multiple GitHub organizations (`secrets.github` keyed by org) and the attacker must control (or be able to emit signed webhooks from) at least one repository in one of those configured organizations — a realistic setup for shared/internal multi-tenant Shipit deployments. The attacker needs no victim-org secret, no session, and no elevated Shipit role; they only need their own org's `webhook_secret`, which they can legitimately obtain by being a member/webhook operator of their own org's GitHub App/webhook configuration. Getting a matching `sha` is straightforward for public repositories (forking preserves identical commit SHAs) or when the victim commit SHA is otherwise observable. The exploit is a single unauthenticated HTTP POST to `/webhooks`, fully repeatable.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and equivalent handlers, e.g. `check_suite`) to commits belonging to stacks/repositories owned by the organization that actually signed the webhook (derived from `repository_owner`/`repository.full_name` in the payload), e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner }).each { ... }`, rejecting or ignoring matches outside that scope.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "status webhook cannot forge CI success for a commit in a different organization" do
  victim_stack = shipit_stacks(:shipit) # repository owned by "victim-org"
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, ...)
  merge_request = victim_stack.merge_requests.create!(number: 1, head: victim_commit, merge_status: "pending")

  # Attacker owns "attacker-org", signs with attacker-org's webhook_secret
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate valid signature for attacker-org
  request.headers['X-Github-Event'] = 'status'
  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => 'attacker-org/some-repo', 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  post :create, body: payload, as: :json

  victim_commit.reload
  # BROKEN BINDING: forged status accepted despite org mismatch
  assert_not_equal 'attacker-org', victim_stack.repository.owner # attacker-org != victim-org
  refute merge_request.all_status_checks_passed?, "forged cross-org status must not satisfy CI checks"
end
```
This asserts the binding `stack.repository.owner == signing_organization` before/after the request and shows it is violated, with `all_status_checks_passed?` incorrectly reflecting the forged status.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L92-99)
```ruby
    def self.by_sha(sha)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (too short)" if sha.to_s.size < 6

      commits = where('sha like ?', "#{sha}%").take(2)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (matches multiple commits)" if commits.size > 1

      commits.first
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
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
      new_status
    end
```

**File:** app/models/shipit/merge_request.rb (L155-245)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end

    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end

    def waiting?
      WAITING_STATUSES.include?(merge_status)
    end

    def need_revalidation?
      timeout = stack.cached_deploy_spec&.revalidate_merge_requests_after
      return false unless timeout

      (revalidated_at + timeout).past?
    end

    def merge_conflict?
      mergeable == false
    end

    def not_mergeable_yet?
      mergeable.nil?
    end

    def schedule_refresh!
      RefreshMergeRequestJob.perform_later(self)
    end

    def closed?
      state == "closed"
    end

    def merged_upstream?
      closed? && merged_at
    end

    def refresh!
      update!(github_pull_request: stack.github_api.pull_request(stack.github_repo_name, number))
      head.refresh_statuses!
      head.refresh_check_runs!
      fetched! if fetching?
      @comparison = nil
    end
```

**File:** app/models/shipit/merge_request.rb (L303-309)
```ruby
    def find_or_create_commit_from_github_by_sha!(sha, attributes)
      if commit = stack.commits.by_sha(sha)
        commit
      else
        github_commit = stack.github_api.commit(stack.github_repo_name, sha)
        stack.commits.create_from_github!(github_commit, attributes)
      end
```
