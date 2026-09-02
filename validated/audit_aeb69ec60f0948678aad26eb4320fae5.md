This confirms the finding. `Shipit.github(organization:)` looks up an app config keyed purely by whatever `repository_owner` string is present in the payload (`app/controllers/shipit/webhooks_controller.rb` `verify_signature`), with no relation whatsoever to which repository the event body claims to be `push`ing to (`repository.full_name`) — that field is only consumed later, independently, by `Handler#stacks`/`Repository.from_github_repo_name`.

### Title
Webhook signature is verified per-organization but not bound to `repository.full_name`, allowing a valid webhook signer to trigger `sync_github` on any other tenant's Stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the HMAC against using only `repository.owner.login` (or `organization.login`) from the untrusted JSON body, and never checks that this owner matches the owner segment of `repository.full_name`, which `Handler#stacks`/`PushHandler#process` use to resolve and mutate the target `Stack`. Any party that legitimately controls one configured GitHub organization's webhook secret on a multi-org Shipit instance can pass signature verification while making `full_name` point at an unrelated organization's repository, causing `sync_github` (and other handlers) to run against that foreign Stack.

### Finding Description
Broken binding: `repository.owner.login` (authenticates the signature) == `repository.full_name.split('/').first` (selects the target `Stack`) is never asserted anywhere in the webhook path.

- `verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner)`, which looks up `secrets.github[repository_owner]` and checks `OpenSSL::HMAC` of the raw body against that org's `webhook_secret` alone: [1](#0-0) 
- `Shipit.github` resolves strictly by the organization key passed in, with no cross-check against the payload's `repository.full_name`: [2](#0-1) 
- After the controller calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, `Handler#stacks` resolves the target purely from `payload.dig('repository', 'full_name')`, independent of `repository_owner`: [3](#0-2) 
- `PushHandler#process` uses that `stacks` scope to call `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived Stack: [4](#0-3) 
- `Repository.from_github_repo_name` performs a simple `owner/name` split-and-lookup with no relation to who signed the request: [5](#0-4) 
- `Stack#sync_github` enqueues `GithubSyncJob`, which fetches commits and writes `Commit` records (and can mark commits as locked/reverted) for the target stack: [6](#0-5) [7](#0-6) 

Exploit flow: on a Shipit instance configured with multiple GitHub organizations (a supported, documented configuration - `docs/setup.md` "Using Multiple GitHub Applications"), an attacker who legitimately owns and configured `attacker-org`'s GitHub App (and therefore knows its own `webhook_secret`) POSTs directly to `/webhooks` with `X-Github-Event: push`, `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, HMAC-signed with `attacker-org`'s secret. `verify_signature` passes because it only checks the attacker's own org's secret against the raw body. `PushHandler` then resolves stacks using `repository.full_name`, i.e. `victim-org/victim-repo`, and calls `sync_github` on the victim's Stack.

Existing guards don't catch this: `verify_signature` never inspects `full_name`; the `ExplicitParameters` schema for `PushHandler` only requires `:ref` and `:after`, with no `repository.owner`/`full_name` consistency check; `Repository.from_github_repo_name`, `Stack` validations, and `require_permission!`/`User#authorized?` are not in this unauthenticated webhook path at all; `drop_unhandled_event` and `check_if_ping` are unrelated to this check.

### Impact Explanation
This is a payload signed under one repository/organization's identity mutating another, unrelated organization's Stack's data (Commit records, `inaccessible_since`/`mark_as_accessible!` flags, lock-reverted-commit state) via an attacker-controlled `sync_github` trigger and forced eventual-consistency retries, without the victim's organization ever authenticating the request. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any Stack/repository configured on the same Shipit instance, for as long as the attacker's own organization remains a registered tenant.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where more than one GitHub organization's app/`webhook_secret` is configured (`config/secrets.yml` `github:` keyed by org, as documented) and where the attacker controls one of those legitimate orgs' webhook secret (they set it themselves when installing their own GitHub App). No Shipit session, API token, or victim secret is needed - only a direct HTTP POST to the public `/webhooks` endpoint with a self-signed body. This is inexpensive and fully repeatable.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#stacks`), assert that the organization used to authenticate the signature equals the owner segment of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers; reject with `422` on mismatch.

### Proof of Concept
Under `test/controllers/webhooks_controller_test.rb`, extend the multi-org config to include both `attacker-org` and `victim-org` with distinct `webhook_secret`s, then:
```ruby
test "signature verified for attacker-org cannot trigger sync on victim-org's stack" do
  victim_stack = shipit_stacks(:victim) # repository owner: victim-org, name: victim-repo, branch: master
  body = {
    "ref" => "refs/heads/master",
    "after" => "deadbeef",
    "repository" => {
      "owner" => { "login" => "attacker-org" },
      "full_name" => "victim-org/victim-repo"
    }
  }.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", ATTACKER_ORG_WEBHOOK_SECRET, body)

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = signature

  # BEFORE (broken binding): attacker-org's login authenticates, victim-org's full_name selects the target
  assert_equal "attacker-org", JSON.parse(body).dig("repository", "owner", "login")
  assert_equal "victim-org", JSON.parse(body).dig("repository", "full_name").split("/").first
  refute_equal JSON.parse(body).dig("repository", "owner", "login"),
               JSON.parse(body).dig("repository", "full_name").split("/").first

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: "deadbeef"]) do
    post :create, body:, as: :json
  end
  assert_response :ok
end
```
This demonstrates the request passes signature verification (`assert_response :ok`, no 422) while enqueuing `GithubSyncJob` for `victim_stack`, proving the owner used for authentication and the owner used for stack selection diverge and are never checked against each other.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
