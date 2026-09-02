### Title
Cross-repository commit-status forgery via SHA-only lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub `status` webhook against the GitHub App belonging to the *organization named in the payload's `repository.owner.login`* [1](#0-0) . Once that HMAC check passes, `Shipit::Webhooks::Handlers::StatusHandler#process` ignores the `repository` field entirely and looks up commits to update **globally, by SHA alone**, across every stack/repository tracked by the Shipit instance [2](#0-1) .

### Finding Description
The equality the deployment-trust model is supposed to enforce is:

`organization that authenticated the webhook == repository whose commit-status data is written`

For `push` events this binding is respected: `PushHandler` scopes writes to `stacks` derived from `Repository.from_github_repo_name(repository_name)`, where `repository_name` comes from `payload.dig('repository', 'full_name')` [3](#0-2) [4](#0-3) .

`StatusHandler` breaks this binding. It never calls `stacks`/`repository_name`; instead it does:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

`Commit` rows are keyed only by `sha` and `stack_id`, with no uniqueness/repository constraint enforced at this lookup site [5](#0-4) . Because the signature check in `verify_signature` only proves "this request came from GitHub App X, installed on organization O" — it says nothing about which specific commit/stack the payload's SHA is allowed to affect — any organization/repository that has the Shipit GitHub App installed can send a legitimately-signed `status` event whose `sha` happens to match a commit that also exists in a *different, unrelated* stack (e.g., because that stack tracks a public repository that has been forked, sharing git history/commit SHAs). Since git commit SHAs are content-addressed and identical across forks/mirrors of the same history, an attacker who controls (or has push access to a repo under) any org configured on the Shipit instance can trigger a real GitHub `status` webhook for a SHA that is shared with a victim stack, and `StatusHandler` will happily write a `Status::replicate_from_github!(stack_id, ...)` (using the *victim's* `stack_id`, taken from `commit.stack_id`) [6](#0-5)  for the victim stack's commit — completely independent of the organization used to satisfy `verify_signature`.

### Impact Explanation
A forged `success` status on a required CI context directly affects `Commit#deployable?`, which requires `success? && !blocked?` unless the stack ignores CI [7](#0-6) . Creating a new `Status` record also triggers `after_commit :schedule_continuous_delivery` [8](#0-7) , meaning a victim stack with continuous deployment enabled can be driven into deploying a commit whose CI status was forged by an attacker who has no relationship to that repository or organization — an unauthorized deploy triggered purely by cross-repository state corruption. This satisfies the Critical bar ("unauthorized deploy") since the attacker never needed credentials, an `ApiClient` token, or write access to the victim repository — only legitimate GitHub webhook delivery from any org already onboarded to the same Shipit instance.

### Likelihood Explanation
Exploitability depends on being able to produce a commit SHA collision between the attacker's own (legitimately webhook-signed) repository and the victim's tracked repository. This is not a cryptographic SHA-1 collision — it only requires the two repositories to share git history, which is trivially achieved for any public/forkable repository (fork the victim repo, or push the exact same commit tree/parent chain into an attacker-controlled repo that also has the GitHub App installed). On any multi-tenant Shipit deployment that onboards more than one organization/repository (which is an explicitly supported and documented configuration — see `secrets_double_github_app.yml` supporting multiple GitHub Apps/orgs), this attack is straightforward to stage without needing any Shipit credentials.

### Recommendation
`StatusHandler#process` should scope the `Commit` lookup to the stack(s) belonging to the repository named in the payload (mirroring `PushHandler`'s use of `stacks`/`repository_name`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Repository.from_github_repo_name(repository_name)`, rather than a bare `Commit.where(sha: params.sha)` across the whole instance.

### Proof of Concept
1. Shipit instance tracks two orgs/repos: `victim-org/app` (a stack in Shipit) and `attacker-org/app-fork` (a fork of it, also with the Shipit GitHub App installed, so its webhooks are validly signed with `attacker-org`'s `webhook_secret`).
2. Attacker identifies a commit `SHA` common to both repos (any commit predating the fork, or one they cherry-pick/reproduce into their fork).
3. Attacker (with normal push/CI access to `attacker-org/app-fork`, no access to `victim-org/app`) causes a `status` webhook to fire for that `SHA` with `state: success` and `context` equal to a context required by `victim-org/app`'s `shipit.yml` (`ci.require`).
4. GitHub signs this payload with `attacker-org`'s `webhook_secret`; `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org` and verification succeeds [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matches the commit belonging to `victim-org/app`'s stack, and calls `create_status_from_github!`, creating a `success` `Status` scoped to the victim's `stack_id` [2](#0-1) [6](#0-5) .
6. If `victim-org/app` has continuous deployment enabled, this newly-satisfied CI status can trigger an automatic, unauthorized deploy of that commit.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L10-18)
```ruby

    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :commit_deployments, dependent: :destroy
    has_many :release_statuses, dependent: :destroy
    belongs_to :merge_request, inverse_of: :merge_commit, optional: true

    deferred_touch stack: :updated_at
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
