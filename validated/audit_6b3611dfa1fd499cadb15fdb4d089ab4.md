### Title
`StatusHandler` binds forged status/commit-status events to any commit by SHA alone, without verifying the payload's `repository` matches the commit's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
### Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to authenticate a webhook against using an attacker-controlled body field, `repository_owner` (`params.dig('repository','owner','login')`), and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) . Crucially, `verify_webhook_signature` fails open when no `webhook_secret` is configured for that organization: `return true unless webhook_secret` [2](#0-1) . This is a real, supported configuration in this codebase — the test fixtures explicitly configure a second org (`OrgTwo`) with `webhook_secret: # nil` [3](#0-2) .

Once the top-level "authentication" of *which organization sent this* passes (or is bypassed because that organization has no secret configured), the actual event handler that processes `status` events, `StatusHandler`, does **not** re-verify that the payload's `repository` corresponds to the commit being modified at all. It only requires `sha` and `state`, and then updates **every** `Commit` row in the entire Shipit installation whose `sha` matches, regardless of which stack/repository owns that commit:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

This breaks the intended binding: **the organization/repository that was authenticated (or exempted from authentication) must equal the repository whose commit state is written**. Here, authentication happens per-organization (via `repository_owner`), but the write (`create_status_from_github!`) is keyed purely by `sha` with no cross-check against `params.repository.full_name` or the commit's actual `stack`/`Repository`. `create_status_from_github!` further schedules `ProcessMergeRequestsJob` and can drive continuous-deployment/merge behavior once a commit transitions to `success` [5](#0-4) .

### Impact Explanation
If any organization configured in `Shipit.github_apps` has no `webhook_secret` set (a supported, documented configuration state in this repo), an unauthenticated attacker can POST an arbitrary JSON body to `/webhooks` with `X-Github-Event: status`, setting `repository.owner.login` to that unsecured organization while embedding any `sha` value they know (commit SHAs are public information, visible on GitHub commit/PR pages) belonging to a commit in a **completely different, properly-secured** stack. `StatusHandler` will happily create a fake "success" status for that commit, which can trigger `ProcessMergeRequestsJob`, deployable-status hooks, and continuous deployment — i.e., an unauthorized deploy or merge. This satisfies the Critical impact bucket ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitability depends entirely on the deployment having at least one configured GitHub organization/App with no `webhook_secret`. This is not merely theoretical: the engine's own multi-org test fixture demonstrates this exact configuration is supported and expected to work (`OrgTwo` with `webhook_secret: nil`) [3](#0-2) , and `verify_webhook_signature` explicitly documents fail-open behavior for that case [2](#0-1) . No `ApiClient` token, `webhook_secret`, GitHub App private key, or repository write access is required — only knowledge of a public commit SHA and the name of any Shipit-configured GitHub organization that omitted a webhook secret.

### Recommendation
- Do not fail-open when `webhook_secret` is blank; require every configured GitHub organization to have a webhook secret, or reject webhooks for organizations without one.
- In `StatusHandler` (and any other handler that mutates commit/stack state keyed only by `sha`), verify that `params.repository.full_name` resolves to the same `Repository`/`Stack` that owns the matched `Commit` before applying the status, instead of matching purely by `Commit.where(sha:)` across the whole installation.

### Proof of Concept
1. Deploy Shipit configured with two GitHub Apps: `VictimOrg` (secured, real `webhook_secret`) and `AttackerOrg` (misconfigured, `webhook_secret` blank/nil) — mirroring the `OrgTwo` fixture in `test/dummy/config/secrets_double_github_app.yml`.
2. Look up a public commit SHA belonging to a stack under `VictimOrg` (visible via GitHub's public commit history/PR pages).
3. POST to `/webhooks` with header `X-Github-Event: status` and body:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/fake",
     "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "AttackerOrg/anything" }
   }
   ```
   No `X-Hub-Signature` value is even checked meaningfully since `AttackerOrg` has no `webhook_secret` (`verify_webhook_signature` returns `true` unconditionally per `lib/shipit/github_app.rb:76-83`).
4. `WebhooksController#verify_signature` passes; `Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha)` and applies the forged `success` status to the victim's commit, potentially triggering `ProcessMergeRequestsJob` / continuous deployment for `VictimOrg`'s stack, as shown by the existing test asserting this side effect on real status transitions [5](#0-4) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
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
      end
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
