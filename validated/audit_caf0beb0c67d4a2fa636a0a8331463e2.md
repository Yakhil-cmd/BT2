Good, this confirms the sync job actually fetches real commits from GitHub via `stack.github_commits` / `fetch_missing_commits` — it doesn't blindly trust `expected_head_sha`, it merely uses it to decide whether to retry. So it can't be used to inject arbitrary unmerged commits; the actual commits still come from GitHub's API for that repository, gated by the app's real installation token. That tempers the "unauthorized deploy" claim to a "cross-tenant sync trigger / signature-binding gap," but the core boundary-crossing flaw — signature verification keyed on one field, repository resolution keyed on a different, uncorrelated field — is real and directly analogous to the reported bug class.

### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while the acted-upon repository is resolved from the unrelated, unvalidated `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment (multiple GitHub Apps/orgs configured under `github:`, each with its own `webhook_secret`), `WebhooksController#verify_signature` selects which org's secret to validate the HMAC signature against using `repository_owner`, taken from `repository.owner.login` (or `organization.login`) in the JSON body. But the event handlers that actually act on the payload resolve the target repository/stack using a completely different field, `repository.full_name`, with no check that its owner segment matches the org whose secret validated the request.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config via `repository_owner`: [1](#0-0) 
and defines that field as: [2](#0-1) 

Once the signature passes, the raw JSON is handed to handlers unmodified: [3](#0-2) 

Every handler resolves the repository/stack to mutate using a different key, `repository.full_name`, via the shared base class: [4](#0-3) 

e.g. `PushHandler` (used to enqueue GitHub sync jobs) and the pull-request handlers (used to archive/unarchive review stacks, capture labels, etc.) all key off `params.repository.full_name`: [5](#0-4) [6](#0-5) 

Because the HMAC (`OpenSSL::HMAC.hexdigest`) is computed over the entire raw request body that the requester controls, an attacker only needs to know **one** organization's `webhook_secret` — e.g. their own org's App secret in a multi-tenant Shipit instance (the documented, supported configuration in `config/secrets.development.example.yml` and `test/dummy/config/secrets_double_github_app.yml`) — to author a fully self-consistent, validly-signed payload where `repository.owner.login` (or `organization.login`) says "OrgA" (so `Shipit.github(organization: "OrgA")` and its secret are selected) while `repository.full_name` says `"OrgB/other-repo"` (a different org/repo tracked by the same Shipit instance). `verify_signature` never cross-checks that these two fields refer to the same organization: [7](#0-6) 

### Impact Explanation
This breaks the trust binding "organization that authenticated == repository that is written." With only a webhook secret belonging to an org they legitimately control, an attacker can forge events acted upon a victim org/repository hosted on the same Shipit instance:
- `push`: enqueues `GithubSyncJob` for the victim's stack with an attacker-chosen `expected_head_sha`, forcing extra sync/API traffic and retry loops against the victim repo — mitigated somewhat because `GithubSyncJob` still fetches real commit data from GitHub via the app's own installation token rather than trusting `expected_head_sha` directly, per `app/jobs/shipit/github_sync_job.rb`.
- `pull_request` (opened/closed/labeled/etc.): can create, archive, or unarchive review stacks and mutate PR label state for a victim org's repository.
- `check_suite`/`status`: can trigger `RefreshCheckRunsJob` or create bogus commit `Status` records against a victim stack's commits.

While the strongest "unauthorized deploy" scenario is blunted by the sync job re-fetching real commit data from GitHub, this is still a cross-tenant state-mutation primitive (creating/archiving review stacks, generating bogus statuses/check-run refreshes, spamming sync jobs) triggerable by any party who legitimately possesses a webhook secret for just one org on a shared, multi-org Shipit install — a boundary that should not be crossable.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (explicitly supported and documented) and requires the attacker to know a `webhook_secret` for at least one configured org — a credential that org administrators legitimately hold. No GitHub-side compromise, TLS interception, or Shipit session is needed; only the ability to construct and sign an HTTP POST to the public `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), validate that the organization identified by `repository_owner` (used to pick the verifying secret) matches the owner segment parsed from `repository.full_name` before processing the event; reject with `422` on mismatch.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), and have Shipit track a repository/stack under `OrgB` (e.g. `OrgB/victim-repo`).
2. As an operator who only knows `OrgA`'s `webhook_secret`, build a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<any-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and `POST` to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner => "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature verifies successfully using the attacker-known `OrgA` secret.
5. `PushHandler#process` then resolves the target stack via `Repository.from_github_repo_name("OrgB/victim-repo")` and enqueues a sync for `OrgB`'s stack — an action the attacker's `OrgA` credential was never authorized to perform.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
