### Title
Webhook signature verification keyed by `repository.owner.login`, but repository handlers act on the unrelated `repository.full_name` field of the same payload - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC `webhook_secret`) is used to validate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`), but every downstream `Shipit::Webhooks::Handlers::Handler` subclass (e.g. `PushHandler`, `LabeledHandler`, `OpenedHandler`) resolves the target `Stack`/`Repository` to act on using the *different* JSON field `repository.full_name`. Because these are two independent fields inside the same JSON body, an attacker who legitimately controls one organization's GitHub App (and therefore knows that organization's `webhook_secret`) can produce a validly-signed payload for their own org while pointing `repository.full_name` at a completely different organization's repository/stack, causing Shipit to sync/act on a victim stack using attacker-controlled data.

### Finding Description
`WebhooksController#verify_signature` chooses the signing secret via: [1](#0-0) 

The organization used for that lookup comes from: [2](#0-1) 

i.e. `params.dig('repository', 'owner', 'login')`, one specific field of the JSON body. The HMAC (`X-Hub-Signature`) that is verified via `github_app.verify_webhook_signature` is checked against the *whole* `request.raw_post`, but the secret used for that check is selected per-organization by `Shipit.github(organization: repository_owner)` — i.e. Shipit is expected to support multiple GitHub App/organization configurations, each with its own `webhook_secret` (per `docs/setup.md`).

Every generic event handler, however, determines which `Repository`/`Stack` the event applies to using an entirely different field of the same payload: [3](#0-2) 

and concretely, e.g.: [4](#0-3) [5](#0-4) 

There is no code anywhere that checks that `repository.full_name`'s owner segment matches `repository.owner.login` (the field used to pick the verifying secret). The trust binding broken is: `organization authenticated by verify_signature == organization/repository actually operated on by the Handler`. These two are read from unrelated, independently attacker-controllable fields of the same JSON body, and the app never asserts equality between them.

### Impact Explanation
An attacker who is a legitimate admin of their *own* GitHub organization's App integration on the Shipit instance (i.e. they know their own org's `webhook_secret`, which is exactly the "unprivileged, only-owns-one-org" attacker model, not a privileged Shipit user) can:

1. Set `repository.owner.login` (and/or `organization.login`) to their own org, so `verify_signature` picks their own known secret and the HMAC passes.
2. Set `repository.full_name` to `"victim-org/victim-repo"`, a totally different, unrelated repository already tracked by Shipit as a `Stack`.
3. Fabricate `ref`/`after` (commit SHA) or PR/label fields at will.

Because `PushHandler`, `LabeledHandler`, `UnlabeledHandler`, `OpenedHandler`, `ReopenedHandler`, `ClosedHandler`, etc. all resolve their target purely from `repository.full_name`, the forged, validly-signed-for-a-different-org event is applied to the victim's stack: `PushHandler#process` invokes `stack.sync_github(expected_head_sha: params.after)` on the victim stack with an attacker-chosen `after` SHA, and PR-label handlers can archive/unarchive review stacks or capture attacker-chosen labels on the victim repository's PRs. This crosses a cross-repository/cross-organization write boundary using credentials that were never issued for, or scoped to, the victim organization — matching the "Critical: cross-repository writes" / "unauthorized deploy" impact bar, since `sync_github` feeding an attacker-chosen `expected_head_sha` can desynchronize the deploy pipeline's notion of the head commit for an organization the attacker does not control.

### Likelihood Explanation
Likelihood is high in any multi-tenant Shipit deployment (the documented, supported configuration: separate GitHub App per organization, each with its own `webhook_secret`). Any org onboarded onto a shared Shipit instance can mount this attack against any other org's repositories with no additional access — they only need control of their own GitHub App webhook configuration, which they are entitled to as an org admin of their own org. The webhook endpoint requires no session or `ApiClient` token.

### Recommendation
In `Handler#stacks`/`Handler#repository_name`, and in every handler that reads `repository.full_name` or `organization.login`, cross-check the repository/organization actually acted upon against the same field used by `WebhooksController#repository_owner` for signature verification (i.e. assert that `repository.full_name.split('/').first == repository.owner.login`, or better, always verify and route using the *same* single authoritative field). Reject the event (422) if they diverge.

### Proof of Concept
1. Shipit is configured with two orgs, `attacker-org` and `victim-org`, each with a distinct GitHub App and `webhook_secret` (per `docs/setup.md` multi-org setup).
2. Attacker knows `attacker-org`'s `webhook_secret` (they administer that GitHub App themselves).
3. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s secret over the exact raw body and sends `POST /webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` and the signature validates successfully. [1](#0-0) 
6. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `stack.sync_github(expected_head_sha: 'deadbeef...')` on the victim's stack, even though the signature was never validated by `victim-org`'s webhook secret. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L59-68)
```ruby
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
