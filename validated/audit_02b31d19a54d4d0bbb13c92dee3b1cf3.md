The core issue is a binding mismatch in the webhook trust model: the GitHub App/organization whose secret is used to **verify** the HMAC signature is chosen from a different payload field than the one used to **select the repository/stack that gets written to**.

## Title
Webhook signature is verified against `repository.owner.login`, but write targets are selected by the unverified `repository.full_name` / global commit `sha` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App config (and thus the HMAC secret) used to authenticate an inbound webhook based on `repository.owner.login` (or `organization.login`) taken from the still-unverified JSON body. [1](#0-0)  Once the signature check passes, every downstream `Shipit::Webhooks::Handlers::Handler` resolves the repository/stack to mutate using a *different* field of the same payload, `repository.full_name`, via `Repository.from_github_repo_name(repository_name)`. [2](#0-1)  `StatusHandler` goes further and doesn't even scope by repository at all, matching commits globally by SHA. [3](#0-2)  Because these two fields are never cross-checked, an actor who legitimately controls the webhook secret for one configured GitHub organization can craft a payload whose `owner.login` matches their own org (so signature verification passes) while `repository.full_name` (or the commit `sha`) references a stack belonging to a completely different organization tracked by the same Shipit instance.

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [4](#0-3)  This only proves the request was signed with *that organization's* secret; it says nothing about which repository the rest of the payload claims to describe.

`create` then dispatches the raw parsed params to every registered handler for the event: [5](#0-4) 

All handlers derive the acted-upon stacks from `payload.dig('repository', 'full_name')`: [2](#0-1)  e.g. `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack matching that repository/branch. [6](#0-5)  Pull-request handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `LabelCapturingHandler`, etc.) similarly resolve `repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and then archive/create/unarchive review stacks or mutate pull-request labels for that resolved repository. [7](#0-6) [8](#0-7) 

Most severely, `StatusHandler` never looks at the repository at all - it matches by SHA across the entire installation: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 

**The broken equality:** *organization whose secret authenticated the request* == *organization/repository the payload's `full_name`/`sha` claims to act upon*. The engine enforces the left-hand check but performs writes based on the right-hand, unrelated field.

**Before the attack:** OrgA and OrgB are both onboarded to the same Shipit instance, each with its own GitHub App and `webhook_secret`. A user only controls/knows OrgA's webhook secret (e.g., because they administer OrgA's GitHub App integration).
**Attacker action:** The attacker directly POSTs to `/github/webhooks` a body where `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/target-repo"` (or, for the `status` event, simply any `sha` value belonging to a commit tracked under OrgB), signed with `X-Hub-Signature` computed using OrgA's secret.
**After:** `verify_signature` succeeds (OrgA's secret matches), and the handler for the event mutates OrgB's stack: `sync_github` pulls in an attacker-chosen `expected_head_sha` for OrgB's stack, review stacks get archived/created for OrgB's PRs, PR labels are rewritten, or — with `StatusHandler` — an arbitrary commit-status (`state: "success"`, any `context`) is fabricated for any commit in the entire installation, which can satisfy `ci.require`/`merge.require` checks and unblock `ProcessMergeRequestsJob`/`MergeRequest#merge!` for a repository the attacker has no relationship to. [9](#0-8) 

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy, rollback or merge" bar explicitly listed as Critical: an attacker who is only entitled to trigger webhooks for organization A can forge state (commit statuses, review-stack lifecycle, sync events) for organization B's repositories/stacks, without ever holding OrgB's GitHub credentials, Shipit session, or API token. Forged "success" statuses can unblock the merge queue and cause Shipit to merge or deploy commits it should not have approved.

### Likelihood Explanation
Medium-High: it requires the attacker to legitimately control (or know the secret for) at least one organization configured on the shared Shipit instance — a realistic scenario for any multi-tenant/multi-org Shipit deployment (the shipped `config/secrets.development.shopify.yml` explicitly supports multiple orgs side by side). [10](#0-9)  No race condition or timing precision is needed, unlike the sandwich-attack analog — a single crafted request suffices.

### Recommendation
Bind the field used for signature-key selection to the field used for repository resolution: verify that `repository.owner.login` (or `organization.login`) used in `verify_signature` is consistent with the owner segment of `repository.full_name`, and reject the webhook otherwise. Additionally, scope `StatusHandler` (and any other handler that doesn't currently do so) to only touch commits belonging to stacks resolved from the same verified organization/repository, rather than matching by SHA across the whole instance.

### Proof of Concept
Not runnable without live infra, but conceptually:
```ruby
payload = {
  "sha" => "<sha-of-a-commit-belonging-to-OrgB-stack>",
  "state" => "success",
  "context" => "ci/required-check",
  "repository" => { "owner" => { "login" => "OrgA" }, "full_name" => "OrgB/target-repo" }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", orgA_webhook_secret, payload)

post "/github/webhooks", body: payload, headers: {
  "X-Github-Event" => "status",
  "X-Hub-Signature" => signature
}
# verify_signature succeeds using OrgA's secret (repository_owner == "OrgA")
# StatusHandler#process matches Commit.where(sha: ...) globally and creates a forged
# "success" status on OrgB's commit, regardless of repository.full_name mismatch.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-53)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
