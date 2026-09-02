### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, allowing cross-repository status forgery and unauthorized PR merges - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, extracted from `params.dig('repository','owner','login')` (or `organization.login`). Once the signature is accepted, every webhook `Handler` (in `app/models/shipit/webhooks/handlers/*`) locates the target `Stack`/`Repository` using a *different* field of the same JSON body: `payload.dig('repository', 'full_name')`. These two fields are never cross-checked against each other, so the field that authenticates the payload is not the field that determines which repository's data gets mutated.

### Finding Description
- `WebhooksController#verify_signature` computes `repository_owner` and fetches `Shipit.github(organization: repository_owner)` to get that organization's `webhook_secret`, then verifies the raw body's HMAC signature against it: [1](#0-0) [2](#0-1) 
- Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw, attacker-supplied JSON to the matching handler(s): [3](#0-2) 
- Every handler (`Handler#stacks`) resolves the target repository purely from `payload.dig('repository', 'full_name')`, a field that is completely independent of `repository.owner.login` used above for signature selection: [4](#0-3) 
- `StatusHandler` (subclass of `Handler`, confirmed by `class StatusHandler < Handler` and by `WebhooksControllerTest`'s `":state create a Status for the specific commit"` test) creates a `Commit::Status` row from the webhook payload (`sha`, `state`, `target_url`, `description`, `context`) scoped to whatever stack/repository is resolved via `full_name`: [5](#0-4) 
- Shipit's merge queue relies exclusively on these locally-stored `Status` rows (populated only from webhooks) to decide whether a pull request is mergeable. `MergeRequest#all_status_checks_passed?`/`#any_status_checks_failed?`/`#any_status_checks_missing?` all read `head.statuses_and_check_runs`, and `ProcessMergeRequestsJob` calls `merge_request.merge!` once these checks pass: [6](#0-5) [7](#0-6) 
- `MergeRequest#merge!` performs the actual cross-repository write using Shipit's own GitHub App credentials: [8](#0-7) 

**Binding broken:** `organization authenticated by HMAC (repository.owner.login)` should equal `repository written to by the handler (repository.full_name)`. Nothing in `verify_signature` or in `Handler#repository_name` enforces this equality.

**Attack path:**
1. Attacker owns/administers a GitHub organization "Attacker-Org" that has *legitimately* installed Shipit's GitHub App/webhook on one of their own repos, so they know that org's `webhook_secret` (it is their own installation's secret, configured by them, per `GithubApp#initialize`: [9](#0-8) ).
2. Attacker crafts an arbitrary `status` webhook JSON body whose top-level `repository.owner.login` = `"Attacker-Org"` (so `verify_signature` picks their own known secret) but whose `repository.full_name` = `"victim-org/victim-repo"` (a completely unrelated, real Shipit stack they have no access to).
3. Attacker computes the HMAC-SHA1 signature for this body with their own known `webhook_secret` and POSTs it directly to Shipit's public `/webhooks` endpoint (no GitHub relay required — this is a direct HTTP request to Shipit).
4. `verify_signature` succeeds because the secret used matches `Attacker-Org`. `StatusHandler` then creates/updates a `Commit::Status(state: 'success', ...)` for an arbitrary commit sha on the victim's stack.
5. If that forged "success" status satisfies the victim stack's required merge-queue statuses, `ProcessMergeRequestsJob` will call `MergeRequest#merge!`, causing Shipit to merge a pull request on the *victim's* repository using Shipit's GitHub App token — an unauthorized, cross-repository merge triggered entirely by an attacker who never had write access, a valid session, or the victim's own webhook secret.

### Impact Explanation
This crosses the "unauthorized deploy, rollback or merge" / "cross-repository writes" Critical bar explicitly called out in the rules: an attacker with control of any one GitHub organization connected to Shipit can forge CI status data for a completely different, victim repository, and drive Shipit's automated merge queue to execute a GitHub PR merge on the victim repo using Shipit's own credentials, without ever authenticating as, or being authorized for, that repository.

### Likelihood Explanation
Requires the attacker to control at least one GitHub organization/webhook_secret already connected to the same Shipit instance (a realistic condition on shared/multi-tenant Shipit deployments serving many orgs) and to know the target victim stack's repo full name (public information, visible in Shipit's UI/API) and a commit sha that is pending in that stack's merge queue. No access to the victim's webhook secret, GitHub credentials, or Shipit session is needed, satisfying the "unprivileged attacker" and "no Shipit session/ApiClient token" constraints.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, cross-validate that the `repository.full_name`'s owner segment matches the `repository.owner.login` (or `organization.login`) that was used to select the verification secret, rejecting the webhook if they diverge. More robustly, derive the webhook_secret lookup key from the same `full_name` field that handlers use to resolve the target `Stack`/`Repository`, so a single field governs both authentication and effect.

### Proof of Concept
```ruby
# Attacker owns "attacker-org" with a known webhook_secret registered in Shipit.
body = {
  sha: "<victim_pending_pr_head_sha>",
  state: "success",
  context: "ci/required-check",
  target_url: "https://example.com",
  repository: {
    owner: { login: "attacker-org" },   # used ONLY to pick verification secret
    full_name: "victim-org/victim-repo" # used to pick the Stack/Repository actually mutated
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_known_webhook_secret, body)

# POST directly to Shipit, bypassing GitHub entirely:
# X-Github-Event: status
# X-Hub-Signature: <signature>
# body: <body>
#
# -> verify_signature passes (secret matches attacker-org)
# -> StatusHandler creates Commit::Status(state: 'success') on victim-org/victim-repo's commit
# -> ProcessMergeRequestsJob later observes all required statuses passed and calls
#    MergeRequest#merge! -> stack.github_api.merge_pull_request(...) on victim-org/victim-repo
```

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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** app/models/shipit/merge_request.rb (L164-185)
```ruby
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
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
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
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
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
```

**File:** lib/shipit/github_app.rb (L44-57)
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
```
