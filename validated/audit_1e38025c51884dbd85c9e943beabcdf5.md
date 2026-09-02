### Title
Webhook signature verification is bound to `repository.owner.login`, but event handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on the payload's `repository.owner.login` (falling back to `organization.login`), while every event handler that actually mutates state (push, status, pull_request, check_suite) resolves the target `Repository`/`Stack` using a *different* field of the same attacker-controlled payload: `repository.full_name`. Nothing ties these two fields together, so a party who legitimately controls one GitHub organization/App installation registered in Shipit's `secrets.yml` can forge a correctly-signed webhook whose `owner.login` matches their own org (passing signature verification) while `full_name` names a completely different, victim repository/stack tracked by the same Shipit instance.

### Finding Description
- `verify_signature` computes the signing organization purely from the request body: `repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`), and uses it to pick a per-org webhook secret via `Shipit.github(organization: repository_owner)` / `verify_webhook_signature`. [1](#0-0) [2](#0-1) 
- Shipit supports multiple GitHub App/organization configs, each with its own independent `webhook_secret`, as shown by the multi-org secrets fixture. [3](#0-2) 
- Every default event handler resolves the repository/stack to act on from `repository.full_name`, a field entirely independent from `owner.login`: [4](#0-3) 
- The `push` handler uses this repository resolution to force-sync any matching stack to an attacker-supplied SHA: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`. [5](#0-4) 
- The `status` handler creates a `Status` record for any commit matching an attacker-supplied `sha`, with an attacker-chosen `state` (e.g. `success`), independent of which repository that commit actually belongs to. [6](#0-5) 
- Commit deployability is gated directly on such statuses: `deployable? = !locked? && (stack.ignore_ci? || (success? && !blocked?))`, so an injected `success` status on the right commit can flip a victim stack's commit into a deployable state. [7](#0-6) 
- `pull_request` handlers similarly key off `params.repository.full_name` alone to find and mutate `PullRequest`/`Stack` records (archive/unarchive review stacks, update PR metadata) with no cross-check against the signing organization. [8](#0-7) 

**Equality that should hold but doesn't:** `organization that authenticated the webhook (repository.owner.login used for signature verification) == organization that owns the repository being written (repository.full_name used to locate the Stack/Commit/PullRequest)`. Before any attacker action, in legitimate GitHub-originated webhooks these two fields always agree, so the binding holds implicitly. After an attacker who controls Org A (and thus knows/derives Org A's `webhook_secret`, either as an app admin or because they are the Shipit operator's own less-trusted org tenant) crafts a raw POST body with `repository.owner.login = "OrgA"` and `repository.full_name = "OrgB/victim-repo"`, correctly signed with Org A's secret, the equality breaks: signature verification passes for Org A, but the handler acts on Org B's stack.

### Impact Explanation
This breaks a repository/organization trust boundary that Shipit relies on to scope which webhook events are trusted for which repositories. Concretely:
- Forged `status` events can mark a victim stack's commit as CI `success`, satisfying `Commit#deployable?` and enabling continuous delivery / manual deploy of a commit that never actually passed CI on the real repository — an unauthorized deploy path.
- Forged `push` events can force `stack.sync_github(expected_head_sha: ...)` on unrelated stacks, and forged `pull_request`/`check_suite` events can archive/unarchive review stacks or otherwise corrupt state for repositories the attacker's organization has no legitimate relationship with.
- This is a cross-repository / cross-organization write achieved purely by controlling one legitimately-configured GitHub organization/App in a multi-tenant Shipit deployment (a supported and documented configuration, per `secrets_double_github_app.yml`), without needing any Shipit session, API token, or the victim organization's webhook secret.

This matches the Critical category "cross-repository writes, or an unauthorized deploy, rollback or merge" from the rubric.

### Likelihood Explanation
Requires only that the attacker control (or be the trusted contact for) one GitHub organization whose App/webhook secret is configured in the same multi-org Shipit instance as the victim organization — a supported deployment topology shown in the repo's own test fixtures for multi-org GitHub App configuration. No repository write access, GitHub App private key, or Shipit credentials for the victim org are needed; only the ability to compute an HMAC with a secret the attacker legitimately possesses for their own org and to POST directly to Shipit's `/github/webhooks` (or equivalent mounted) endpoint, bypassing GitHub entirely.

### Recommendation
Bind the two fields together: after selecting the signing organization from `repository.owner.login`/`organization.login`, verify that every downstream `Repository`/`Stack` lookup derived from `repository.full_name` (or other body fields) belongs to that same verified organization before processing the event. Concretely, in `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name`, assert that the resolved `Repository#owner` equals the organization used in `WebhooksController#verify_signature`, and reject/short-circuit the event otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), where OrgA is the attacker's own org and OrgB hosts the victim's tracked stack `OrgB/victim-repo`.
2. As an OrgA administrator/App owner, compute `sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)` for a crafted JSON body:
   ```json
   {
     "sha": "<victim-commit-sha>",
     "state": "success",
     "context": "ci/required",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. POST this body to Shipit's webhook endpoint with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, looks up OrgA's `webhook_secret`, and the signature check passes.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a `success` status for the victim's commit in `OrgB/victim-repo`, even though the request was never signed by OrgB's secret — demonstrating the cross-organization write.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
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
