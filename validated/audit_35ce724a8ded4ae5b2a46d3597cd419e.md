### Title
Webhook signature verification selects the signing organization from an unverified payload field, letting an attacker impersonate any tracked repository once one onboarded organization has no `webhook_secret` configured - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/`webhook_secret` to verify a webhook against using `repository_owner`, a value taken straight from the unauthenticated JSON body, before the signature has been validated. Every event handler, however, resolves the target `Stack`/`Repository` from a completely different, also-unverified field: `repository.full_name`. Because the field used to select the verification key and the field used to select the acted-upon repository are never cross-checked, an attacker who can produce a "valid" (or trivially bypassable) signature for *any* organization configured on the Shipit instance can make the webhook processing pipeline act on a repository belonging to a *different* organization.

### Finding Description
`verify_signature` derives the organization purely from request body content: [1](#0-0) [2](#0-1) 

That organization is used to fetch the corresponding `GitHubApp` and its `webhook_secret`: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when the resolved organization has no `webhook_secret` configured — a state explicitly documented as "optional": [4](#0-3) [5](#0-4) 

Once signature verification "passes" (either because the chosen organization has no secret, or because the attacker legitimately controls that organization's app installation), the request body is dispatched to handlers, none of which re-checks the organization used above. Every handler resolves its target repository from `repository.full_name` alone: [6](#0-5) [7](#0-6) 

This is exactly the "organization that authenticated versus the repository that is written" binding: `repository_owner` (used to select and validate the signing secret) and `repository.full_name` (used to select the `Stack` the event acts on) are two independent, attacker-controlled JSON fields in the same unauthenticated payload, and the code never asserts `repository.full_name` belongs to `repository_owner`.

Before/after the attacker's request:
- Before: signature verification is meant to prove "this payload originates from GitHub for organization X", and the payload's `repository.full_name` should therefore also belong to organization X.
- After: an attacker can set `repository.owner.login` to organization X (any onboarded org with no `webhook_secret`, or one the attacker controls) while setting `repository.full_name` to `victim-org/victim-repo`, a stack belonging to a completely different, unrelated organization Y also served by the same Shipit instance. The signature check succeeds against X, but the `PushHandler` (or other handlers) will act on Y's tracked stack.

### Impact Explanation
A successful `push` event forged this way calls `stack.sync_github(expected_head_sha: params.after)`, which enqueues `GithubSyncJob`: [8](#0-7) 

This job uses the *real* GitHub App credentials for the victim organization/stack to fetch commits and, if `continuous_deployment` is enabled on that stack, can lead to an automatic, unauthorized deploy of attacker-influenced state on a repository/stack the attacker has no legitimate access to — matching the Critical "unauthorized deploy" impact criterion. Other handlers (`membership`, `pull_request`, `check_suite`, `status`) similarly act on data scoped by `repository.full_name`/`organization.login` without validating consistency with the verified signer, allowing cross-tenant state manipulation (creating/archiving review stacks, mutating team membership records, injecting commit statuses) for any repository tracked by the Shipit instance, not just the organization whose secret was actually used to authenticate the request.

### Likelihood Explanation
This requires a Shipit deployment that serves multiple GitHub organizations (a supported and documented configuration — see `secrets_double_github_app.yml` and `docs/setup.md`), and requires that at least one onboarded organization has no `webhook_secret` set — a state the setup documentation explicitly calls "optional," making it a realistic and even likely misconfiguration for internal/dev-tier organizations sharing the same production Shipit instance as fully secured ones. No Shipit session, API token, or possession of a victim organization's `webhook_secret` is needed; the attacker only needs to know (or exploit the absence of) the secret of the one organization used to pass the signature check, then freely set `repository.full_name` to any repository already tracked by the instance.

### Recommendation
Cross-validate that the `repository.owner.login` (or `organization.login`) value used to select and verify the webhook signature matches the owner segment of `repository.full_name` before dispatching to handlers, and reject the request otherwise. Additionally, consider requiring a non-blank `webhook_secret` for every configured organization (fail closed rather than allowing an implicit bypass when unset), and have `verify_signature` derive the organization from the resolved `Stack`/`Repository`'s configured GitHub App rather than from client-supplied JSON.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (attacker-influenced or with `webhook_secret` unset) and `OrgB` (victim org, `webhook_secret` set, tracking `orgb/victim-repo` with `continuous_deployment: true`).
2. Send:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # irrelevant if OrgA has no webhook_secret

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "orgb/victim-repo"
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (garbage) `X-Hub-Signature` header.
4. `PushHandler` resolves `repository_name` from `repository.full_name` = `orgb/victim-repo`, finds `OrgB`'s tracked `Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, enqueuing `GithubSyncJob` for `OrgB`'s real GitHub App/token — a cross-organization action never authenticated against `OrgB`'s own secret.

*(Note: I could not find any additional cross-check between the verified organization and `repository.full_name` anywhere in `app/controllers/shipit/webhooks_controller.rb` or `app/models/shipit/webhooks/**`; based on the code available in the index, this binding is unenforced end to end.)*

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
