### Title
Webhook `status` event authenticated per-organization but applied to any commit database-wide, regardless of which organization/repository it belongs to - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController` verifies inbound GitHub webhook signatures using the webhook secret configured for the organization named in the payload's `repository.owner.login` (or `organization.login`) field, then dispatches the parsed payload to the matching `Shipit::Webhooks::Handlers` class. `StatusHandler`, which processes `status` events, never re-checks that the commit it mutates belongs to the repository/organization whose secret was actually verified — it looks up commits globally by SHA across the entire database. On a multi-tenant Shipit instance (the documented "Using Multiple Github Applications" setup), this breaks the binding: *organization whose signature authenticated the request* ≠ *repository/commit that is actually written*.

### Finding Description
`WebhooksController#verify_signature` derives `repository_owner` from the payload and fetches that organization's `GitHubApp` to verify `X-Hub-Signature` against the raw body: [1](#0-0) [2](#0-1) 

Once the signature is accepted for that organization's secret, the entire (attacker-influenceable) JSON body is handed to handlers: [3](#0-2) 

Most handlers scope their side effects to a `Repository` looked up from `repository.full_name` (a different field of the same payload than the one used to pick the verifying secret), via `Handler#stacks`/`Repository.from_github_repo_name`: [4](#0-3) [5](#0-4) 

But `StatusHandler` does not use this scoping at all — it mutates **any** `Commit` row in the database whose SHA matches the attacker-chosen `sha` param, with no repository/organization filter whatsoever: [6](#0-5) 

Because `Repository` records (and thus `Commit`/`Stack` records) are stored in one global table keyed only by `owner/name` and are not otherwise namespaced per configured GitHub App/organization, a webhook whose signature was validated for Organization A's secret can carry a `sha` that matches a commit belonging to a completely unrelated Stack owned by Organization B. `StatusHandler` will happily attach the forged status (`state`, `context`, `description`, `target_url`) to Organization B's commit.

This is precisely the "verified field vs. acted-upon field" mismatch from the reference report: the signature check validates the claimed *organization*, but the actual write target (`Commit` by `sha`) is never checked against that organization/repository.

### Impact Explanation
Commit statuses drive Shipit's CI-gating logic for merges and deploys (a commit is treated as "green"/deployable once its statuses report success). An entity that legitimately administers **any** organization configured in this Shipit instance (and thus knows that organization's `webhook_secret`) can forge a signed `status` event that flips the CI status of an arbitrary commit belonging to a **different** organization's stack to `success`, without ever having push or admin access to that other organization's GitHub repository. This can unblock merges/deploys that are gated on CI status for a repository the attacker has no rights to — a cross-organization/cross-repository write that can lead to an unauthorized deploy or merge, satisfying the Critical impact bar ("cross-repository writes" / "unauthorized deploy... or merge").

### Likelihood Explanation
Exploitability requires the attacker to control (or be a legitimate but low-trust admin of) one organization's GitHub App/webhook secret on a shared, multi-organization Shipit deployment — a configuration explicitly supported and documented (`docs/setup.md`'s "Using Multiple Github Applications" section, and `lib/shipit.rb#github_app_config`). Given that setup, forging a `status` payload is trivial: no GitHub interaction is even required, only a raw HTTP POST to the public `/webhooks` endpoint with a correctly computed HMAC using the known secret. No repository-write access to the target organization, no `ApiClient` token, and no privileged Shipit account are needed, satisfying the "unprivileged attacker" bar for organizations other than the one they administer.

### Recommendation
In `StatusHandler#process` (and any other handler that does not already use `Handler#stacks`/`repository_name`), scope the lookup to commits belonging to the verified organization/repository, e.g. resolve `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` first (as other handlers do), and restrict `Commit.where(sha:, stack: repository.stacks)` (or equivalent) instead of querying `Commit` globally. Additionally, consider validating that `repository.owner.login`/`organization.login` (used to select the verifying secret) matches the owner embedded in `repository.full_name` before dispatching to any handler, so a single mismatch check protects all current and future handlers.

### Proof of Concept
Given a Shipit instance configured with two GitHub Apps/organizations (`orgA`, `orgB`) as in `test/dummy/config/secrets_double_github_app.yml`, and a `Commit` with `sha = "deadbeef...","stack_id"` belonging to a Stack under `orgB/private-repo`:

```
POST /webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC_SHA1(orgA_webhook_secret, body)>
Content-Type: application/json

{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "target_url": "https://example.com",
  "repository": { "owner": { "login": "orgA" } }
}
```

`verify_signature` succeeds because it verifies against `orgA`'s secret (matched via `repository.owner.login`), which the attacker legitimately controls. `StatusHandler#process` then executes `Commit.where(sha: "deadbeef...")`, finds the `orgB` commit (no organization/repo filter applied), and calls `create_status_from_github!`, attaching a forged "success" status to a commit the attacker never had access to, in an organization they do not administer.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
