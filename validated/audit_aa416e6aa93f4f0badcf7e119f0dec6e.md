### Title
Webhook signature verification is scoped to `repository.owner.login`, but event handlers act on the unrelated `repository.full_name` field, breaking organization-authenticated-vs-repository-written binding - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against by reading the attacker-controlled `repository.owner.login` field out of the still-unverified JSON body. Once the signature is confirmed valid for *that* organization, the raw payload is handed unmodified to every registered handler, which independently derives the actual target `Repository`/`Stack` from a *different* attacker-controlled field, `repository.full_name`. Nothing ties the two fields together, so a payload that is validly signed for organization A can name organization B's repository as the action target.

### Finding Description
`verify_signature` computes `repository_owner` from the raw JSON payload and uses it purely to pick the `Shipit::GithubApp` (and thus the `webhook_secret`) used for HMAC verification: [1](#0-0) [2](#0-1) 

After the signature check passes, `create` dispatches the *entire raw payload* to every handler registered for the event: [3](#0-2) 

Every handler resolves the `Stack`/`Repository` it will mutate from a second, independent field of the same payload, `repository.full_name`, via `Repository.from_github_repo_name`: [4](#0-3) [5](#0-4) 

Nothing enforces `repository.owner.login == repository.full_name.split('/').first`. Concretely: `PushHandler` calls `stack.sync_github` for whatever stack matches `repository.full_name`: [6](#0-5) 

and the pull-request handlers create/archive/unarchive review stacks for the repository matched from `repository.full_name`: [7](#0-6) [8](#0-7) 

The binding the engine implicitly relies on is:
`organization_authenticated_by_signature(repository.owner.login) == organization_owning(repository.full_name)`

This equality is never checked. Shipit is explicitly multi-tenant — each organization configures its own `webhook_secret` under `Shipit.github(organization:)` — so an attacker who legitimately controls the webhook secret for **one** organization onboarded to a shared Shipit instance can craft a payload where `repository.owner.login` names their own organization (so the HMAC check passes) while `repository.full_name` names a repository/stack belonging to a **different** organization on the same Shipit instance. The signature is valid, but the actions taken (`sync_github`, review-stack `archive!`/`unarchive!`/`create!`) are performed against a repository the attacker never authenticated for.

### Impact Explanation
This is a cross-repository/cross-organization write: an attacker who only controls their own org's webhook secret can trigger `GithubSyncJob` and review-stack provisioning/archival/unarchival actions on a victim organization's stacks by simply setting `repository.full_name` to the victim's repo while keeping `repository.owner.login` set to their own org. This matches the "Critical - cross-repository writes / unauthorized deploy/rollback" impact bar, since it lets one tenant of a shared Shipit deployment cause state changes (sync, archive, unarchive, provisioning) on another tenant's stacks without ever authenticating against that tenant's secret.

### Likelihood Explanation
Exploitation only requires an attacker to be a legitimate operator of *some* organization configured on the shared Shipit instance (a normal, low-privilege onboarding scenario for a multi-tenant deploy engine) plus knowledge of that instance hosting other organizations' repositories — no access to the victim's GitHub App, webhook secret, or Shipit session/API token is required. The request is a single crafted HTTP POST to `/webhooks`.

### Recommendation
After `verify_signature` succeeds, re-derive `repository.full_name`'s owner and assert it matches the `repository_owner` used to select the verifying `webhook_secret` before dispatching to handlers; alternatively, have each `Handler` re-validate that `payload.dig('repository','owner','login')` matches the resolved `Repository#owner` before performing any mutation.

### Proof of Concept
1. Organization `attacker-org` is configured in Shipit's secrets with its own `webhook_secret` (a routine, unprivileged onboarding step for any org using this shared instance).
2. Organization `victim-org/victim-repo` is a separate tenant on the same Shipit instance with an open PR / active stack.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request`, body:
```json
{
  "action": "labeled",
  "number": 1,
  "pull_request": { "state": "open", "labels": [{"name": "..."}], ... },
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" },
  "sender": {"login": "attacker"}
}
```
4. `X-Hub-Signature` is computed with `attacker-org`'s known `webhook_secret` over this exact body — `verify_signature` looks up `Shipit.github(organization: 'attacker-org')` (from `repository.owner.login`) and the HMAC check passes. [1](#0-0) 
5. `LabeledHandler`/`PushHandler` resolve the target `Repository`/`Stack` from `repository.full_name = "victim-org/victim-repo"` and archive/unarchive/sync that stack, even though the signature never authenticated against `victim-org`'s secret. [8](#0-7)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
