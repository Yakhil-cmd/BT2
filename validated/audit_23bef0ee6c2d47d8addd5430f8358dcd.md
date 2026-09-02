### Title
Push webhook signature check keys off `repository.owner.login` while the handler acts on `repository.full_name`, letting an attacker with access to any no-secret org spoof pushes to arbitrary repositories - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) to verify against using `params.dig('repository', 'owner', 'login')`, but `Shipit::Webhooks::Handlers::Handler#stacks` resolves the target `Repository`/`Stack` using the independent field `payload.dig('repository', 'full_name')`. Because a single JSON body can set these two fields inconsistently, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's `webhook_secret` is blank, an attacker only needs one Shipit-configured GitHub org with no `webhook_secret` to forge a `push` event that mutates a stack belonging to a completely different, fully-secured org/repository.

### Finding Description
The broken binding: the organization used to verify the signature (`repository.owner.login`) must equal the organization/repository whose state the handler mutates (`repository.full_name`). Tracing the code shows these are two unrelated reads of the same attacker-controlled JSON body:

- `WebhooksController#repository_owner` (app/controllers/shipit/webhooks_controller.rb:59-62) reads `params.dig('repository', 'owner', 'login')` and passes it to `Shipit.github(organization: repository_owner)`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) does `return true unless webhook_secret` — if the org resolved above has a blank `webhook_secret` in `secrets.yml`, verification is skipped entirely regardless of the `X-Hub-Signature` header.
- On success, `WebhooksController#create` dispatches to `Shipit::Webhooks::Handlers::PushHandler`, whose `process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17).
- `stacks` is defined in the shared `Handler` base class (app/models/shipit/webhooks/handlers/handler.rb:32-38) as `Repository.from_github_repo_name(repository_name)&.stacks`, where `repository_name` is `payload.dig('repository', 'full_name')` — a **different** field than the one used for signature verification.

Exploit: an attacker who controls (or can freely register) any organization that Shipit has configured without a `webhook_secret` (e.g. a low-value/legacy org in a multi-org Shipit deployment, per the `github_organizations`/`github_app_config` multi-org support seen in `test/dummy/config/secrets_double_github_app.yml`) crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-with-no-secret" },
    "full_name": "victim-org/victim-repo"
  }
}
```
and POSTs it to `/webhooks` with `X-Github-Event: push` and any/no `X-Hub-Signature`. `verify_signature` resolves `Shipit.github(organization: "org-with-no-secret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking the signature at all. The request proceeds to `PushHandler`, which resolves stacks via `full_name` = `"victim-org/victim-repo"`, entirely bypassing the fact that the verified org and the mutated repository differ. This drives `stack.sync_github(expected_head_sha: params.after)` on stacks the attacker never authenticated for.

No existing guard catches this: `drop_unhandled_event` only filters by event type; `verify_signature` never cross-checks `full_name` against `owner.login`; the `ExplicitParameters` schema in `PushHandler` only requires `ref`/`after` and does not constrain `repository`; and `Repository.from_github_repo_name` performs no ownership check against the verifying org.

### Impact Explanation
An attacker can force `stack.sync_github` (which fetches/appends commits and can trigger continuous deployment) on any stack/repository configured in Shipit, as long as any single organization in the Shipit instance's multi-org config lacks a `webhook_secret`. This is a cross-tenant/cross-repository state manipulation where one org's (attacker's) unauthenticated payload mutates another org's stack — matching the Critical impact category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Requires: (1) Shipit configured with multiple GitHub orgs (documented, supported feature — `docs/setup.md` "Using Multiple Github Applications"), and (2) at least one of those orgs has a blank/unset `webhook_secret` — the shipped example configs (`config/secrets.development.example.yml`, `secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) all default `webhook_secret` to nil, suggesting this is a realistic operational misconfiguration. Given that precondition, the attack costs a single unauthenticated HTTP POST and is fully repeatable against any stack.

### Recommendation
In `WebhooksController#verify_signature`, or in `Handler#stacks`, enforce that the organization used to resolve/verify the webhook secret matches the organization owning `repository.full_name` (e.g. compare `repository.owner.login` against the repo's actual namespace before syncing, or derive `repository_owner` from the same trusted field used for repository resolution). Additionally, treat a blank `webhook_secret` as a hard configuration error rather than an implicit bypass, or require explicit opt-in for unsigned orgs.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "push payload with mismatched owner org and repository.full_name mutates a stack in another org" do
  # Precondition: multi-org secrets fixture where OrgOne has no webhook_secret
  # (e.g. test/dummy/config/secrets_double_github_app.yml)
  victim_stack = shipit_stacks(:shipit) # belongs to a repo not owned by "OrgOne"

  payload = {
    ref: "refs/heads/#{victim_stack.branch}",
    after: "deadbeef" * 5,
    repository: {
      owner: { login: 'OrgOne' }, # org with blank webhook_secret
      full_name: victim_stack.repository.full_name # victim org/repo
    }
  }.to_json

  Shipit::Stack.any_instance.expects(:sync_github).with(expected_head_sha: 'deadbeef' * 5)

  post '/webhooks', params: payload, headers: {
    'X-Github-Event' => 'push',
    'X-Hub-Signature' => 'sha1=bogus',
    'Content-Type' => 'application/json'
  }

  assert_response :ok
  # Assert: organization verifying signature ('OrgOne', no secret) != organization owning victim_stack
  refute_equal 'OrgOne', victim_stack.repository.owner
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```
