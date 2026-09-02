### Title
Webhook signature verification keyed on attacker-controlled `repository.owner.login`/`organization.login` diverges from the repository actually acted on via `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and thus which `webhook_secret`) to check the HMAC signature against using a value taken directly out of the unauthenticated, attacker-supplied JSON body (`repository.owner.login` or `organization.login`). The event handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` using a *different* field from the same body, `repository.full_name` [1](#0-0) . Nothing ties these two fields together, so the "organization whose secret authenticated the request" and "the repository that is written to" are not the same binding.

### Finding Description
`/webhooks` is mounted with no authentication other than the signature check [2](#0-1) , so any unprivileged actor on the internet can POST directly to it, bypassing GitHub delivery entirely.

`verify_signature` computes the org used to look up the GitHub App/secret purely from the request body: [3](#0-2) [4](#0-3) 

Verification itself is optional per-organization: if no `webhook_secret` is configured for that org, `verify_webhook_signature` returns `true` unconditionally: [5](#0-4) 

Shipit explicitly supports multiple GitHub organizations, each with its own independent `webhook_secret`, and documents `webhook_secret` as optional per app: [6](#0-5) [7](#0-6) 

Once `verify_signature` passes, `create` dispatches the *entire* parsed body to all registered handlers for the event [8](#0-7) . `PushHandler` (and other handlers) resolve which `Stack`/`Repository` to operate on using `repository.full_name`, not `repository.owner.login`: [9](#0-8) [10](#0-9) 

**The broken binding (as an equality):**
`organization used to select/pass signature verification` (`repository.owner.login` ∨ `organization.login`) is expected to equal `organization that owns the repository actually acted upon` (`repository.full_name`'s owner). Nothing in `WebhooksController` or `Handler` enforces this equality.

**Before the attack:** each GitHub org tracked by Shipit is isolated — a webhook claiming to originate from org A can only be verified using org A's secret, and is expected to only affect org A's repositories.

**After the attack (payload crafted by an unprivileged actor):** an attacker sets `repository.owner.login`/`organization.login` = `OrgWithoutSecret` (any org configured in Shipit's multi-org config that happens to have no `webhook_secret` set — an explicitly supported, documented configuration) while setting `repository.full_name` = `VictimOrg/victim-repo` (a real Stack tracked by Shipit belonging to a different, secret-protected org). `verify_signature` looks up `OrgWithoutSecret`'s (secret-less) `GitHubApp`, which returns `true` unconditionally, and the request proceeds. `PushHandler` then resolves the target stack from `repository.full_name = VictimOrg/victim-repo` and calls `stack.sync_github(expected_head_sha: params.after)`, queuing a `GithubSyncJob` for the victim stack with an attacker-chosen `expected_head_sha` [11](#0-10) .

This lets an unprivileged party who has no relationship to `VictimOrg` — and does not know `VictimOrg`'s `webhook_secret` — trigger sync jobs, statuses, check-suite refreshes, membership/team creation, or pull-request-driven review-stack archival/unarchival for `VictimOrg`'s stacks, purely by picking a *different, secret-less* organization name to satisfy the signature check while pointing the payload's actual repository fields at the victim.

### Impact Explanation
This crosses a credential/authorization boundary the way an unauthorized cross-repository write does: an attacker with no access to `VictimOrg`, no webhook secret, and no Shipit session can cause Shipit to act on `VictimOrg`'s tracked stack (queue syncs against the real GitHub repo, create commit statuses, flip review-stack archived state via labeled/unlabeled handlers, add memberships/teams, etc.) as if a legitimately signed webhook for that org had arrived. This matches the "cross-repository writes" / unauthorized-action category, since the write target (repository/stack acted upon) is decoupled from the authenticated identity (organization whose secret passed verification).

### Likelihood Explanation
Requires: (1) the deployment to track more than one GitHub organization (documented, supported feature), and (2) at least one tracked organization configured without a `webhook_secret` (explicitly documented as optional). Given both, exploitation requires no credentials, no session, and no knowledge of any secret — only the ability to POST arbitrary JSON to the public `/webhooks` endpoint. Likelihood depends entirely on operator configuration choices that the engine itself permits and documents, so it is realistic but not guaranteed in every deployment.

### Recommendation
Bind the field used to select/verify the webhook signature to the same field the handlers use to determine the affected repository/stack — i.e., derive both consistently from `repository.full_name` (or require that `repository.owner.login` match the owner segment of `repository.full_name` before dispatching to handlers). Additionally, do not allow signature verification to be a silent no-op: if `webhook_secret` is blank for an organization, either reject the webhook or restrict handler dispatch so a payload verified under one organization's (even secret-less) config can never act on another organization's repositories.

### Proof of Concept
1. Shipit is configured with two GitHub orgs: `VictimOrg` (has `webhook_secret` set, tracks stack `VictimOrg/victim-repo`) and `NoSecretOrg` (configured per docs with `webhook_secret:` left blank), as in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker (no credentials, no session) sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "organization": { "login": "NoSecretOrg" },
  "repository": { "owner": { "login": "NoSecretOrg" }, "full_name": "VictimOrg/victim-repo" }
}
```
3. `verify_signature` computes `repository_owner = "NoSecretOrg"`, calls `Shipit.github(organization: "NoSecretOrg")`, whose `verify_webhook_signature` returns `true` unconditionally because no secret is configured.
4. `PushHandler#process` resolves `stacks` via `repository.full_name = "VictimOrg/victim-repo"`, matching the real victim stack, and enqueues `GithubSyncJob` with the attacker-supplied `after` SHA — despite the request never carrying a valid signature for `VictimOrg`.

### Citations

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

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
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
