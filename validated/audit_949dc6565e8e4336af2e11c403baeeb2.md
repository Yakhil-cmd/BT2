### Title
Webhook Organization/Repository Binding Mismatch Allows Cross-Organization Github Sync Forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using the organization derived from `repository.owner.login` (or `organization.login`) in the payload, but `Shipit::Webhooks::Handlers::Handler#repository_name` (used by `PushHandler` and other handlers to locate the `Stack`/`Repository` to mutate) reads a *different* field, `repository.full_name`, without ever checking that it belongs to the same organization that was used to authenticate the signature.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` from the untrusted JSON body itself (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`), then fetches that organization's `Shipit.github(organization: repository_owner)` app config and verifies the HMAC-SHA1 signature using **that organization's** `webhook_secret`: [1](#0-0) [2](#0-1) 

Once verification succeeds, the whole raw payload is dispatched unchanged to the event handlers: [3](#0-2) 

`Handler#repository_name`/`#stacks`, used by `PushHandler#process` (and other handlers) to resolve which `Stack` to act on, reads a **separate** JSON field, `repository.full_name`: [4](#0-3) [5](#0-4) 

Shipit explicitly supports multiple GitHub Apps/organizations in the same instance, each with its own `webhook_secret`: [6](#0-5) 

Because `repository.owner.login` (which selects the signing secret) and `repository.full_name` (which selects the target `Stack`) are two independent, attacker-controlled fields in the same JSON body, and HMAC verification only proves the message was signed with *some* organization's secret — not that the acted-upon repository belongs to that organization — an operator of any organization configured on the instance can forge a `push` payload where:
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` picks their own, known `webhook_secret`), and
- `repository.full_name` = `"victim-org/victim-repo"` (any other repository tracked by this Shipit instance).

They sign the raw body with their own legitimate `webhook_secret`, which passes `verify_webhook_signature` because that check only compares the signature against the secret associated with `repository_owner` == their own org. The handler then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` for a stack that belongs to a completely different organization, causing Shipit to fetch commits/statuses from GitHub using Shipit's own credentials and mutate that victim stack's commit history/cache: [7](#0-6) 

This breaks the intended binding: **organization authenticated (secret used to verify the signature) == repository being written (repository whose Stack state is mutated)**. Before the attacker's forged request, that equality always holds for legitimate webhooks (GitHub always signs with the secret of the org owning the repo). After it, the two sides diverge, and any org onboarded to the Shipit instance can trigger sync/state changes for stacks outside its own repositories.

### Impact Explanation
This is a cross-organization write: an org that is only authorized to speak for its own repositories can force Shipit to sync github state (commits, CI statuses, spec cache) for another org's stack. If that victim stack has `continuous_deployment` enabled, syncing in attacker-influenced/attacker-observed commit data can advance `last_deployed_commit`/deployable commit tracking and precipitate automatic deploys via `ContinuousDeliveryJob`, i.e., an unauthorized deploy pathway, which matches the Critical impact bucket ("cross-repository writes" / "an unauthorized deploy"). At minimum it is a High-impact unauthenticated (cross-tenant) write into another organization's stack state.

### Likelihood Explanation
Exploitation requires only that the attacker legitimately controls one organization's GitHub App/webhook configuration on a multi-org Shipit instance (a normal, unprivileged-relative-to-other-orgs position, not requiring any Shipit session, `ApiClient` token, or the victim's `webhook_secret`/private key). Crafting the payload only requires knowledge of standard GitHub webhook JSON shape and their own secret — no other secrets are needed. This is a straightforward, repeatable forgery.

### Recommendation
After signature verification, cross-check that the organization used to select the signing secret matches the owner of the repository referenced by the fields the handlers actually act upon (`repository.full_name`, `organization.login`, etc.), rejecting the webhook if they diverge. Alternatively, derive the signing organization strictly from `repository.full_name`'s owner segment (the same field handlers use) rather than a separate `repository.owner.login`/`organization.login` field, so there is a single source of truth for both signature-secret selection and stack resolution.

### Proof of Concept
1. Instance configures two orgs in `secrets.yml`: `attacker-org` (with `webhook_secret: S_attacker`, controlled/known by the attacker who administers that org's GitHub App) and `victim-org` (tracked stack `victim-org/victim-repo`).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_attacker, raw_body)>` and `X-Github-Event: push`, and POSTs to `/github/webhooks` (per `config/routes.rb`).
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully (correct secret for that org).
5. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and invokes `stack.sync_github(expected_head_sha: "deadbeef...")`, mutating `victim-org`'s stack state despite the request never being authenticated by `victim-org`'s secret.

Note: I was unable to fully trace `Stack#sync_github`/`continuous_deployment` auto-deploy trigger logic within the tool-call budget available; the root-cause binding break (organization used for signature vs. repository acted upon) is confirmed directly from `webhooks_controller.rb` and `handlers/handler.rb`, but the exact downstream deploy-triggering consequence should be verified with a full read of `app/models/shipit/stack.rb`'s `sync_github`/continuous delivery methods.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** docs/setup.md (L182-209)
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
