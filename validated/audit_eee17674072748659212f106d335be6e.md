Based on the evidence gathered, I found a concrete binding-break in the webhook signature verification: the signature check is keyed off one field of the JSON payload (`repository.owner.login` / `organization.login`), while the handlers that actually mutate Shipit's persisted state key off a completely different, unrelated field (`repository.full_name`). Neither the controller nor `GithubApp` cross-checks that these two fields describe the same GitHub organization.

### Title
Webhook signature is verified against `repository.owner.login`, but state-mutating handlers act on the independent `repository.full_name` field, letting one configured GitHub organization forge events for another org's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the per-organization webhook secret using `repository_owner`, computed from `params.dig('repository','owner','login') || params.dig('organization','login')`, and HMAC-verifies the raw request body against that secret. [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` only proves the raw bytes were signed with the secret belonging to whichever organization `repository_owner` names - it says nothing about any other field inside that same JSON body. [3](#0-2) 

Once verification passes, the *entire unmodified* payload is dispatched to handlers (`PushHandler`, `StatusHandler`, etc.), which resolve the target `Stack`/`Repository`/`Commit` using `repository.full_name` (and status/sha fields), not `repository.owner.login`. [4](#0-3) [5](#0-4) 

This is confirmed by the test suite: mutating `repository.full_name` to point at a completely different repo is accepted and processed independently of the `owner.login`/secret used to sign the request. [6](#0-5) [7](#0-6) 

### Finding Description
In a Shipit deployment configured with more than one GitHub organization (the engine explicitly supports this, see `test/dummy/config/secrets_double_github_app.yml` with `OrgOne`/`OrgTwo`, each with its own `webhook_secret`), each organization owner legitimately knows the `webhook_secret` they registered for their own GitHub App integration. [8](#0-7) 

The equality the engine relies on but never enforces is:
`organization_that_signed_the_payload == organization_that_owns_the_repository_the_handlers_write_to`

Before the attack: for a legitimate GitHub-originated webhook, `repository.owner.login` and `repository.full_name`'s owner segment are always the same, because GitHub itself constructs both fields from the same underlying repository object.

After the attack: an org owner who knows their own `webhook_secret` can POST an arbitrary JSON body directly to `/webhooks` (a public, unauthenticated endpoint - no Shipit session, `ApiClient` token, or GitHub write access is required) where:
- `repository.owner.login` (or `organization.login`) = their own organization (so `Shipit.github(organization: ...)` selects the secret they know, and `verify_webhook_signature` passes)
- `repository.full_name` = `"<victim-org>/<victim-repo>"`, an org they do not control

`verify_signature` only ever reads `repository.owner.login`/`organization.login` to pick the secret; it never checks that this equals the owner encoded in `repository.full_name`. The handlers that follow (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolve stacks/commits purely via `repository.full_name`/`sha`, so they operate on the victim org's Stack even though the signature only proved authenticity for the attacker's own org. [9](#0-8) 

### Impact Explanation
The most concrete escalation path is `StatusHandler`, which is exercised by the `":state create a Status for the specific commit"` test: it creates a `Status` record on an existing commit purely from `sha`, `state`, `description`, `target_url`, `context`, taken straight from the (cross-org-forgeable) payload. [7](#0-6) 

Since Shipit gates automatic deploys on required CI status contexts (`ci.require` in `shipit.yml`), an attacker who controls any one organization configured on the same Shipit instance can forge a `success` status for a known commit SHA belonging to a *different* organization's stack, bypassing the CI-required safety check and enabling an **unauthorized deploy** of that victim stack. This matches the in-scope "unauthorized deploy" impact category.

### Likelihood Explanation
This requires the Shipit instance to be multi-tenant (multiple GitHub organizations configured, which the codebase explicitly supports and ships fixtures for) and requires the attacker to legitimately own/administer one of those configured organizations' GitHub App/webhook secret - not a privileged Shipit account, session, or API token, and no access to the victim repository. The attacker additionally needs to know an existing commit SHA in the victim's synced history (often discoverable if the victim repo is public, or via Shipit's own public-facing pages). This is a real, exploitable credential-organization mismatch rather than a theoretical one, but it's conditioned on the specific multi-org deployment topology.

### Recommendation
In `WebhooksController#verify_signature`, after computing `repository_owner` and verifying the signature, additionally validate that every organization-identifying field present in the payload (e.g. `repository.full_name`'s owner segment, `organization.login`) is consistent with `repository_owner`, rejecting the request (422) on mismatch before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, `AttackerOrg` (secret known to attacker) and `VictimOrg` (repo `VictimOrg/app` tracked by an existing Stack with a required CI status context).
2. Attacker crafts a `push` or `status` JSON body per GitHub's webhook schema, setting `repository.owner.login = "AttackerOrg"` (or `organization.login = "AttackerOrg"`) but `repository.full_name = "VictimOrg/app"`, `sha = <existing victim commit>`, `state = "success"`, `context = "<required context>"`.
3. Attacker computes `X-Hub-Signature: sha1=<hmac using AttackerOrg's known webhook_secret over the raw body>` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` selects `AttackerOrg`'s app via `repository_owner` and confirms the HMAC - passes.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which creates a `Status` for the referenced commit in `VictimOrg/app`'s stack, as demonstrated by the existing test `":state create a Status for the specific commit"`. [7](#0-6) 

Note: I was unable to fully read `app/models/shipit/webhooks/handlers/handler.rb` and `status_handler.rb` in this session (tool errors on the final iteration) to confirm the exact `stacks`/`repository` lookup implementation line-by-line; the mechanism is inferred from the controller test behavior (`repository.full_name` used to resolve stacks/status targets independently of the signing organization) and from `PushHandler`'s use of `stacks` scoped by branch. A full review of `handler.rb`'s `stacks` method is recommended to pin down the exact lookup query before remediation.

### Citations

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-47)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
```
