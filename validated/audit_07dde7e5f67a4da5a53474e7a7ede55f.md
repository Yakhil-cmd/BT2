### Title
Webhook Signature Verification Selects a Different Organization's Secret Than the Repository Actually Written To - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which organization's `webhook_secret` to validate an incoming payload against by reading `repository.owner.login` (or `organization.login`) out of the **same untrusted JSON body** that the event handlers later use to decide which `Stack`/`Repository`/`Commit` to mutate. Because these two uses of attacker-controlled payload fields are never bound together, an attacker can pick an organization that has no `webhook_secret` configured (which makes verification a no-op) while making the rest of the payload (`repository.full_name`, `sha`, `state`, etc.) target a completely different, "protected" organization/repository.

### Finding Description
Signature verification is implemented as: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the request body, and is used to fetch a `GithubApp` instance for that organization: [3](#0-2) 

Critically, `verify_webhook_signature` **short-circuits to `true` whenever `webhook_secret` is blank for that organization** (`return true unless webhook_secret`). In any Shipit deployment supporting multiple GitHub organizations (a supported configuration, as shown by the `Shipit::GithubHook::Organization` model and per-org `Shipit.github(organization:)` lookups), it is plausible for at least one configured organization to have no webhook secret set (e.g., a newly added org, or one temporarily left unconfigured).

The event handlers that actually act on the payload determine *which* repository/stack/commit to mutate independently, from the very same JSON body, e.g. the status handler creates a `Status`/`CommitStatus` directly from payload fields without any additional GitHub-side verification: [4](#0-3) 

and the push handler resolves target stacks purely from repository/branch fields in the payload without re-checking which organization was used for signature validation: [5](#0-4) 

The equality that should hold but is broken:

`organization used to select webhook_secret for HMAC verification == organization/repository that the handler subsequently writes to`

An attacker can set `repository.owner.login` (or `organization.login`) to an org with no `webhook_secret` (verification always passes, regardless of `X-Hub-Signature`), while setting `repository.full_name` / commit `sha` to a repository belonging to an organization that *does* have a webhook secret configured, and target its `Stack`/`Commit`.

### Impact Explanation
This lets an unauthenticated, unprivileged attacker forge webhook events (e.g. `status`, `push`, `check_suite`) for any repository/stack tracked by the Shipit instance, as long as any other org configured in the same instance lacks a webhook secret — entirely bypassing HMAC verification for the "protected" org's repository. Concretely:
- Forged `status` events let an attacker write arbitrary `CommitStatus` rows (state/description/target_url) for a specific commit SHA in a protected stack, which is used by Shipit to gate `Commit#deployable?` / CI requirements before a deploy is allowed or before continuous deployment auto-triggers. Faking a passing CI status on an unreviewed commit can lead to an **unauthorized deploy** of that commit.
- Forged `push` events can trigger `GithubSyncJob` for arbitrary stacks, and other event types have similarly permissive write behavior keyed off attacker-supplied `repository`/`organization` payload fields.

This crosses the required boundary of "an unauthorized deploy, rollback or merge" without any credential, GitHub App secret, or session, and matches the analog class explicitly called out in the rules ("an organization that authenticated versus the repository that is written").

### Likelihood Explanation
Requires: (a) the Shipit instance to support/host more than one GitHub organization (a documented, supported configuration via `Shipit::GithubHook::Organization` / per-org `Shipit.github`), and (b) at least one of those organizations to have a blank `webhook_secret`. Given webhook secrets are optional per the setup docs ("Webhook secret (optional)"), this is a realistic operational configuration, not a purely theoretical one. No credentials, tokens, or privileged access are required by the attacker — only network access to the public `/webhooks` endpoint.

### Recommendation
Bind the signature-verification organization to the same identity used for authorization of the write. Concretely:
- After determining the target `Stack`/`Repository` inside each handler, verify that the organization actually used to validate the HMAC (`repository_owner` from `verify_signature`) matches the owner of the repository the handler is about to mutate; reject the request if they differ.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in a multi-organization deployment; either require a webhook secret for every configured organization or fail closed when it is missing rather than treating it as "verified."

### Proof of Concept
1. Configure Shipit with two organizations: `org-a` (no `webhook_secret` set) and `org-b` (`webhook_secret` set, hosts the target stack `org-b/secret-repo`).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: status` and an arbitrary/blank `X-Hub-Signature`, and JSON body:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/secret-repo" },
  "sha": "<commit sha under org-b/secret-repo>",
  "state": "success",
  "context": "ci/tests",
  "target_url": "https://example.com",
  "description": "forged",
  "created_at": "2026-09-01T00:00:00Z"
}
```
3. `verify_signature` calls `Shipit.github(organization: "org-a")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (no HMAC check performed).
4. The request proceeds to `Shipit::Webhooks.for_event('status')`, which processes the payload against `org-b/secret-repo`'s commit, writing a forged passing `Status`, exactly as demonstrated by the existing test that shows a `Status` record created directly from webhook JSON fields ( [4](#0-3) ), without any per-repository signature binding.
5. If that commit is subsequently deployed (manually or via continuous deployment), Shipit believes CI passed even though no legitimate GitHub webhook for `org-b` was ever sent.

Note: I was unable to inspect `app/models/shipit/webhooks/handlers/handler.rb` (base `stacks`/repository-resolution logic) in this session due to a tool failure on the final iteration, so the exact resolution method (`Repository.from_github_repo_name` or similar) for turning `repository.full_name` into a `Stack` could not be directly confirmed from source, though it is strongly implied by the `PushHandler` code and the `Repository.from_github_repo_name` usage seen elsewhere in the codebase (e.g. `app/controllers/shipit/api/stacks_controller.rb`).

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
