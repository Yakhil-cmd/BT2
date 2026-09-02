### Title
Webhook signature verification is scoped to the payload's `repository.owner.login`/`organization.login`, but every handler acts on the independently-read `repository.full_name` — allowing cross-organization stack writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based solely on `repository_owner`, which is read from the attacker-supplied JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`): [1](#0-0) [2](#0-1) 

Verification only proves that the raw POST body was signed with the webhook secret configured for *that organization* — it does not constrain which repository/stack the payload is subsequently allowed to mutate. Once `head(:ok)`/no early-return occurs, `create` dispatches the entire raw, attacker-controlled `params` hash to every registered handler for the event: [3](#0-2) 

Every handler, however, resolves the target repository/stack independently, from a *different* field of the same payload — `repository.full_name` — with no cross-check against `repository_owner`/`organization.login` that was actually used to select the verification secret: [4](#0-3) 

Concretely:
- `PushHandler` looks up stacks via `stacks` (i.e. `Repository.from_github_repo_name(repository_name)`) and triggers `stack.sync_github(expected_head_sha: params.after)` [5](#0-4) 
- `PullRequest::ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`, `LabelCapturingHandler` resolve `repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and archive/unarchive review stacks or overwrite pull request labels based on that unrelated repository's configuration [6](#0-5) [7](#0-6) 

Because the JSON body is fully attacker-controlled (it is not itself GitHub's payload once it passes HMAC verification against a secret the attacker legitimately possesses for their *own* onboarded organization), an operator of Organization A — who has legitimately been granted a GitHub App installation on Shipit for one of their own repositories, and therefore knows/can trigger deliveries signed with Organization A's `webhook_secret` — can set `repository.owner.login` (and/or `organization.login`) to `"OrgA"` so the signature check passes against Organization A's secret, while independently setting `repository.full_name` to `"OrgB/some-unrelated-repo"`. This breaks the intended binding: **organization that authenticated == repository that is written**. The verified identity (Organization A) is never checked against the entity actually mutated (a stack belonging to Organization B, a completely different tenant configured in the same Shipit instance — Shipit explicitly supports multiple organizations per instance, each with its own webhook secret, as documented in `config/secrets.development.shopify.yml`).

### Impact Explanation
This yields unauthenticated cross-repository/cross-organization writes: an attacker who controls only their own org's webhook secret can force GitHub-sync jobs, archive/unarchive review stacks, or rewrite pull-request label state for any other organization's repository/stack tracked by the same Shipit instance, without ever needing credentials, API tokens, or write access to the victim's repository. This matches the Critical "cross-repository writes" impact category.

### Likelihood Explanation
Any tenant onboarded to a shared, multi-organization Shipit deployment (a supported, documented configuration — see multiple orgs in `config/secrets.development.shopify.yml`) already possesses everything needed: their own organization's webhook secret and the ability to send arbitrary signed POST requests to the public `/github/webhooks` endpoint. No social engineering, GitHub App private key, or Shipit session/API token is required — only an unprivileged tenant's own legitimately-issued webhook secret.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`), enforce that the organization/owner used to select the verification secret matches the owner of `repository.full_name` acted upon by the handler, rejecting the webhook (422) if they diverge. Alternatively, derive the target repository/stack exclusively from the verified organization context rather than trusting an independent field of the unauthenticated-until-verified JSON body.

### Proof of Concept
1. Shipit instance is configured (as documented) with two tenants, e.g. `orgA` and `orgB`, each with distinct `webhook_secret`s, each having onboarded at least one repository/stack.
2. Attacker is a legitimate operator of `orgA` and knows/can compute `orgA`'s `webhook_secret` (e.g., via their own installed GitHub App or a webhook delivery they control).
3. Attacker crafts a JSON body for the `push` event:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` using `orgA`'s `webhook_secret` over the exact raw body and POSTs it to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "orgA")` and succeeds, because the signature matches `orgA`'s secret [1](#0-0) .
6. `PushHandler#process` resolves `stacks` from `repository.full_name` = `"orgB/victim-repo"` and calls `stack.sync_github(expected_head_sha: ...)` on `orgB`'s stack [8](#0-7)  — a write triggered on a repository/organization the attacker never authenticated for.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-69)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
