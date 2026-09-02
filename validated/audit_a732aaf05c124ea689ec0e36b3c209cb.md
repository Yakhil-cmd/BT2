### Title
Webhook signature is verified against the organization named inside the unsigned lookup path, but the affected repository/stack is resolved from a different field in the same attacker-controlled payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to validate a request against based on `params.dig('repository', 'owner', 'login')` (or `params.dig('organization', 'login')`), taken straight from the untrusted request body. [1](#0-0) [2](#0-1)  Every downstream handler, however, resolves the actual repository/stack to act on from a *different* field of the same body: `payload.dig('repository', 'full_name')`. [3](#0-2)  Nothing binds these two fields together, so on a multi-tenant Shipit install (the engine explicitly supports several organizations each with its own GitHub App/webhook secret, as shown in `test/dummy/config/secrets_double_github_app.yml`), an attacker who legitimately controls one onboarded organization (and thus knows/can produce a validly-signed payload for it) can set `repository.owner.login` to their own org (so signature verification passes with their own secret) while setting `repository.full_name` to `"other-org/other-repo"` belonging to a different tenant on the same instance.

### Finding Description
This mirrors the PoolTogether analog: a value that gets acted upon (`repository.full_name`, i.e. "the repository that is written") is never the value the trust check actually authenticates ("the organization that authenticated", i.e. `repository.owner.login`). Both are attacker-controlled JSON fields inside the same HTTP body that only needs to be `sha1`-HMAC'd with *some* org's webhook secret — but which org's secret is used is itself selected by reading an unauthenticated field from that same body:
- `repository_owner` (used to select the `GithubApp`/secret for verification) = `params.dig('repository','owner','login')` or `params.dig('organization','login')`. [2](#0-1) 
- Every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull_request handlers) resolves the target `stacks`/`repository` via `payload.dig('repository', 'full_name')` through `Repository.from_github_repo_name`. [3](#0-2) 

Because `verify_signature` only proves "this body was HMAC-signed by the org named in `repository.owner.login`", not "this body concerns a repository actually owned by that org", an attacker with a valid webhook secret for `OrgTwo` can forge a request where `repository.owner.login = "OrgTwo"` (so `Shipit.github(organization: "OrgTwo")` is selected and the HMAC computed with `OrgTwo`'s secret checks out) but `repository.full_name = "OrgOne/victim-repo"`. The signature check passes, and the handler then acts on `OrgOne/victim-repo`'s stacks.

### Impact Explanation
This crosses a repository-ownership boundary using only a credential valid for a different repository/org, which is the same class of binding violation targeted by this scan ("an organization that authenticated versus the repository that is written"). Depending on the handler invoked this can:
- Inject forged commit `Status` records for arbitrary shas on a foreign stack via `StatusHandler#process` / `Commit#create_status_from_github!`. [4](#0-3) 
- Trigger `GithubSyncJob` against a foreign stack via `PushHandler#process` → `stack.sync_github`. [5](#0-4) [6](#0-5) 
- Archive/unarchive review stacks belonging to a foreign repository via the pull-request handlers. [7](#0-6) 

Because `stack.sync_github` / `GithubSyncJob` fetch commits using the app's own installation token for the (attacker-chosen) `full_name` repo, and forged CI statuses can influence `deployable?`/required-status checks that gate continuous deployment, this can plausibly cascade into an unauthorized deploy on a repository the attacker does not own — which is one of the accepted Critical/High impact categories for this scan. I was not able to fully trace whether a forged `Status` alone is sufficient to make `Commit#deployable?` pass end-to-end for continuous delivery in the time available (partial exploration of `app/models/shipit/commit.rb` and `Status::Group` was not completed), so the "unauthorized deploy" leg of the impact is plausible but not fully proven here.

### Likelihood Explanation
Exploitation requires the attacker to be an authenticated tenant on a shared multi-org Shipit deployment (i.e., they control at least one organization's GitHub App/webhook secret that is already configured in `secrets.yml`, as the engine explicitly supports, per `secrets_double_github_app.yml`). This is a real but non-trivial precondition — it is not "any random internet user," but it is also not a privileged Shipit account, `ApiClient` token, or repository write access on the *victim* repo, so it does not fall under the excluded "requires privileged account/repository write access" cases. Given the check is purely a body-authenticity check with no ownership binding, exploitation is otherwise straightforward (a single crafted POST to `/webhooks`).

### Recommendation
After `verify_webhook_signature` succeeds, additionally assert that `repository.full_name`'s owner segment equals the `repository_owner`/`organization.login` value that selected the `GithubApp` used for verification (or, more robustly, verify the signature using the GitHub App installation associated with the actual target repository looked up from `full_name`, not from a separately-read owner field). Reject the webhook if these disagree.

### Proof of Concept
1. Attacker legitimately controls `OrgTwo`, which is configured in this shared Shipit instance's `secrets.yml` with its own `webhook_secret` (per the supported multi-org pattern in `secrets_double_github_app.yml`).
2. Attacker crafts a `push` (or `status`/`pull_request`) webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "OrgOne/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgTwo_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgTwo")` (from `repository_owner`) and successfully verifies the signature using `OrgTwo`'s secret. [1](#0-0) 
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgOne/victim-repo")` and triggers `GithubSyncJob` against `OrgOne`'s stack, even though the request was never authenticated by `OrgOne`. [3](#0-2) [5](#0-4)

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

**File:** app/jobs/shipit/github_sync_job.rb (L18-24)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
