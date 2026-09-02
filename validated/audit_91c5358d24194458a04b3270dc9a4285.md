### Title
Webhook signature verified against organization named in payload, not against the repository that handlers act on - allows cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against based on `repository_owner`, a value read straight out of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). Once the signature checks out for that organization, the controller dispatches the entire payload to the event handlers, which independently pick the target `Stack`/`Repository` using a different field of the same body: `repository.full_name`. Nothing ties the two together, so a signature that is valid for organization A says nothing about whether the repository actually acted upon also belongs to organization A.

### Finding Description
`verify_signature` resolves the signing secret with `Shipit.github(organization: repository_owner)` and then checks `X-Hub-Signature` against `request.raw_post` using that organization's `webhook_secret` [1](#0-0) . `repository_owner` is derived purely from the JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .

Once verification passes, `create` re-parses the same body and fans it out to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) . Every handler resolves the actual target repository/stack from `payload.dig('repository', 'full_name')`, completely independent of the field used for signature verification: `Repository.from_github_repo_name(repository_name)&.stacks` [4](#0-3) . `Repository.from_github_repo_name` simply splits `owner/name` and does a `find_by` with no relation to whichever organization's secret validated the request [5](#0-4) .

This breaks the intended binding: `organization that authenticated == repository that is written`. The webhook secret is configured per organization (`Shipit.github(organization:)`) and is typically known to that organization's own GitHub admins, since GitHub computes the signature from the org/repo's configured webhook secret when firing real events, and any admin of that org can view/rotate it. Because Shipit trusts whichever organization name appears in the JSON body to select the verification secret, and separately trusts an unrelated field (`repository.full_name`) in that same body to select the actor's target, an attacker who legitimately administers "their own" organization onboarded to this Shipit instance (and thus knows/controls that org's `webhook_secret`) can hand-craft a payload where:
- `repository.owner.login` / `organization.login` = "OrgA" (their own org - used only to pick the verification secret)
- `repository.full_name` = "OrgB/victim-repo" (a totally different, unrelated organization's repository registered on the same Shipit instance)

Sign the raw body with OrgA's known secret, and the request passes `verify_signature`, then the handler layer looks up and acts on OrgB's `victim-repo` stacks.

Concretely with the `push` handler:
```ruby
# app/models/shipit/webhooks/handlers/push_handler.rb
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
```
`stack.sync_github` enqueues `GithubSyncJob` for that (victim, unrelated-org) stack, using the requester-supplied `after` SHA [6](#0-5) [7](#0-6) . The job fetches commits via the app's own GitHub credentials for that stack and, since `sync_github_if_necessary`/`after_commit :sync_github` also runs on ordinary stack updates, forcing an out-of-band sync on a foreign stack the attacker does not administer causes state changes (`GithubSyncJob#perform`) unrelated to that organization's own authorization [8](#0-7) . The same decoupling affects the pull-request handlers (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabelCapturingHandler`), all of which resolve the acted-upon repository solely via `params.repository.full_name`, independent of the org used for signature verification [9](#0-8) [10](#0-9) .

This matches the analog bug class from the report: a value ("items_count"/vector length) is used to decide what happens, while the actual bound/allocated structure ("items" vector, length 1) doesn't correspond to it - here the *verified* scope (organization A's secret) doesn't correspond to the *acted-upon* scope (repository named in a sibling field, potentially owned by organization B).

### Impact Explanation
This is a cross-organization/cross-repository write: a party who only controls their own onboarded organization's webhook secret can force Shipit to enqueue GitHub-sync and pull-request/review-stack lifecycle actions (archive/unarchive review stacks, label capture, provisioning) against a completely different organization's stacks that they have no legitimate access to. That satisfies the "cross-repository writes" / "unauthorized deploy or rollback trigger" Critical-tier criterion, since `GithubSyncJob` runs with the app's own GitHub credentials against the victim repository and can trigger downstream `CacheDeploySpecJob`/deploy pipeline activity outside the attacker's authorization boundary.

### Likelihood Explanation
The only prerequisite is administering (or otherwise knowing the webhook secret of) any single organization already onboarded to the shared Shipit instance - no Shipit session, API token, or GitHub App private key is required, which is exactly the kind of unprivileged-attacker path this scan is scoped to. Multi-tenant Shipit deployments (one instance serving several GitHub organizations, as `Shipit.github(organization:)`/`config/environments` implies) are the realistic target; a single-organization deployment is not exposed to this specific cross-tenant angle, but the code path itself unconditionally decouples "org verified" from "repo acted upon" regardless of deployment size.

### Recommendation
Bind signature verification to the same repository identity that handlers act upon, rather than looking up secrets by an independently-sourced org name in the payload:
- After computing `repository_name` (`repository.full_name`) in the handler layer/controller, resolve the owning `Repository`/its parent GitHub App configuration and verify the signature against *that* organization's secret, not the raw `repository.owner.login`/`organization.login` field.
- Alternatively, once the signature is verified for organization X, hard-fail (or drop) the payload if `repository.full_name`'s owner segment does not case-insensitively match X.
- Apply the same cross-check to the `organization.login` fallback path used for `membership` events.

### Proof of Concept
1. Attacker administers "OrgA", already onboarded to the shared Shipit instance, and knows OrgA's `webhook_secret` (visible/rotatable by any OrgA GitHub admin).
2. Attacker crafts a `push` (or `pull_request`) JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, HMAC matches, request is accepted [11](#0-10) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on OrgB's stack, entirely outside OrgA's authorization boundary [6](#0-5) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
