### Title
Webhook signature is verified against the payload's `repository.owner.login`/`organization.login` while all event handlers act on the unauthenticated `repository.full_name` field, enabling cross-repository forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook using the organization name found at `repository.owner.login` (or `organization.login`), but every event handler that actually performs a write (syncing commits, archiving/unarchiving review stacks, updating pull requests, etc.) resolves the target repository from a *different* field of the same payload: `repository.full_name`. Because these two identifiers are never cross-checked against each other, anyone who legitimately controls the webhook secret for **any one** organization configured on a multi-tenant Shipit instance can self-sign a payload whose `repository.owner.login` matches their own org (so signature verification passes) while `repository.full_name` names a completely different, victim repository/stack. This lets the attacker's own valid signature authorize writes against a repository they do not own.

### Finding Description
`verify_signature` picks the verification key like this: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GitHubApp` instance (and thus `webhook_secret`) configured for that specific organization. Shipit natively supports one `webhook_secret` per organization, as shown by the multi-org config format: [3](#0-2) 

Once the signature is accepted, `create` blindly dispatches the raw JSON body to handlers: [4](#0-3) 

Every handler resolves its target repository/stack from `repository.full_name`, not from the organization that was used to authenticate the request: [5](#0-4) [6](#0-5) [7](#0-6) 

There is no check anywhere that `repository.full_name`'s owner segment equals `repository_owner` (the value that selected the signing secret). The webhook HMAC only proves "whoever holds Org X's `webhook_secret` produced this exact JSON body" — it says nothing about which repository the JSON body's `repository.full_name` field claims to reference, because that field is fully attacker-controlled content, not a signed identity claim tied to the verification key selection.

**Binding broken:** organization that authenticated (`repository_owner` used to pick the `webhook_secret`) ≠ repository that is written (`repository.full_name` used by every handler to locate the `Stack`/`Repository`/`PullRequest` to mutate).

### Impact Explanation
Any organization admin who has legitimately configured their own GitHub App/webhook secret on a shared, multi-tenant Shipit deployment (a supported, documented configuration) can craft and self-sign a webhook body where `repository.owner.login` = their own org (to pass `verify_signature`) but `repository.full_name` = `"victim-org/victim-repo"`. This is accepted as a fully valid, verified webhook and dispatched to handlers that act on the victim's stacks:
- `PushHandler` triggers `GithubSyncJob` on the victim stack with an attacker-chosen `expected_head_sha` [8](#0-7) , which can desynchronize the victim stack's deploy/undeployed-commit state.
- `PullRequest::ClosedHandler`/`ReopenedHandler`/`LabeledHandler` can archive/unarchive review stacks belonging to the victim repository [9](#0-8) .
- `EditedHandler` can overwrite stored `github_pull_request` data for the victim's pull requests [10](#0-9) .

This is a cross-repository write achieved purely by controlling one org's own credentials, satisfying the "cross-repository writes" Critical-impact criterion.

### Likelihood Explanation
Exploitation requires only that the attacker be a legitimate, low-privileged tenant/org admin on the shared Shipit instance (already possessing a valid `webhook_secret` for their own org) — no GitHub write access, Shipit session, or `ApiClient` token to the victim's stack is needed. Crafting the forged payload is trivial (standard HMAC-SHA1 signing over an attacker-authored JSON body).

### Recommendation
In `Handler#repository_name` (and everywhere handlers resolve the target repository/organization), verify that the resolved repository's owner matches the organization that was used to select the webhook secret in `WebhooksController#verify_signature` — e.g., pass the authenticated `repository_owner` into the handler dispatch and reject/ignore events where `repository.full_name`'s owner segment does not match it.

### Proof of Concept
1. Attacker legitimately registers `AttackerOrg` on the shared Shipit instance and knows `AttackerOrg`'s `webhook_secret`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(AttackerOrg_webhook_secret, body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "AttackerOrg")` and successfully verifies the signature [1](#0-0) .
5. `PushHandler` resolves the stack via `Repository.from_github_repo_name("VictimOrg/victim-repo")` [5](#0-4)  and enqueues `GithubSyncJob` for the victim's stack with the attacker's chosen `after` sha, despite the attacker never having been authenticated for `VictimOrg`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```
