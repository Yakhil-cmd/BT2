### Title
Webhook signature validated against the payload's `repository.owner`/`organization` while the acted-upon repository is resolved from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/`webhook_secret` to validate a signature by reading `repository.owner.login` (or `organization.login`) out of the **attacker-supplied JSON body**, while every event `Handler` resolves the `Stack`/`Repository` that will actually be acted upon from a different field of that same untrusted body: `repository.full_name`. Nothing enforces that these two fields agree. In a multi-tenant Shipit deployment (Shipit explicitly supports configuring several GitHub organizations, each with its own `webhook_secret`, see `config/secrets.development.shopify.yml`), a tenant who legitimately administers their own GitHub App/org can forge a webhook whose `repository.owner.login` matches their own org (so it verifies with a secret they legitimately hold) but whose `repository.full_name` points at a repository belonging to a completely different, victim organization hosted on the same Shipit instance.

### Finding Description
The binding that should hold is: `organization that authenticated == organization whose repository/stack is written`.

Verification side: [1](#0-0) [2](#0-1) 

`repository_owner` is taken verbatim from the JSON body (`params.dig('repository','owner','login')`) and used to pick which `GitHubApp`/`webhook_secret` (via `Shipit.github(organization: repository_owner)`) validates `X-Hub-Signature`.

Action side, used by every handler (including `PushHandler`): [3](#0-2) [4](#0-3) 

`Handler#stacks` resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` — a completely independent field of the same attacker-controlled JSON body. Because the raw JSON is fully attacker-authored (only the HMAC over the raw bytes is checked), nothing forces `repository.full_name`'s owner segment to equal `repository.owner.login`. A tenant who owns/administers *any* organization configured in this Shipit instance can therefore sign a payload with their own known `webhook_secret` while setting `repository.full_name` to `"victim-org/victim-repo"`.

### Impact Explanation
This crosses an authentication-to-repository binding for a shared/multi-tenant Shipit install: it lets a webhook that is only proven to originate from organization A be treated as data about organization B. Concretely, `PushHandler#process` will call `stack.sync_github(expected_head_sha: params.after)` on a stack that belongs to organization B, letting org A force a resync to an arbitrary SHA it did not push. The same `Handler#stacks`/`repository_name` resolution path is shared by every repository-scoped handler (status, check_suite, pull_request, etc., all subclass `Handler`), so the same technique lets an attacker inject a forged commit status or check result against a commit in another organization's repository. Since `ci.require` and blocking statuses gate the merge queue and deploy pipeline, a forged "success" status can help satisfy CI requirements that gate an unauthorized deploy/merge in a stack the attacker does not otherwise control — this reaches the "unauthorized deploy, rollback or merge" impact bar.

### Likelihood Explanation
Requires only that the Shipit operator hosts more than one GitHub organization/tenant (a documented, supported configuration — see `config/secrets.development.shopify.yml`), and that the attacker legitimately administers one of those organizations' GitHub Apps (their own `webhook_secret`, not a stolen one). No access to the victim organization's credentials, `ApiClient` token, or Shipit session is required — only the ability to send a raw HTTP POST to `/webhooks` with a validly-signed-for-their-own-org body.

### Recommendation
After verifying the HMAC signature, cross-check that the organization used to select the secret (`repository_owner`) matches the owner segment of `repository.full_name` (and any other repository identifiers used downstream by handlers) before dispatching to `Shipit::Webhooks.for_event`. Reject the webhook (422) on mismatch.

### Proof of Concept
1. Shipit instance is configured with two tenants, `orgA` (attacker, legitimate GitHub App admin, knows `webhook_secret_A`) and `orgB` (victim), per `config/secrets.development.shopify.yml`-style multi-org config.
2. Attacker builds a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, raw_body)>` and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner = "orgA"`, loads `orgA`'s app, and the signature verifies successfully.
5. `WebhooksController#create` dispatches to `PushHandler`, whose `Handler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` — a repository belonging to the victim tenant — and enqueues `GithubSyncJob`/updates state for `orgB`'s stack, despite the request only ever being authenticated as `orgA`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-18)
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
