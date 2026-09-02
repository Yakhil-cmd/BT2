### Title
Webhook signature is verified against an attacker-selected organization while the handlers act on a different, unverified `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to check the HMAC against based on an unauthenticated field of the very payload it is trying to verify, then every event handler independently re-reads a *different* unauthenticated field of that same payload to decide which repository/stack to act on. The organization whose secret authorizes the request is never bound to the repository the request actually mutates.

### Finding Description
`verify_signature` derives the signing organization purely from the JSON body itself, before the signature has been validated: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) and is used to pick `Shipit.github(organization: repository_owner)`, i.e. the specific org's `webhook_secret` in a multi-org configuration (`lib/shipit.rb#github`, `github_app_config`). The HMAC is checked against `request.raw_post` using that org's secret.

However, once the signature check "passes" (using Org A's secret), the actual event handlers determine *which repository/stack to mutate* using a completely separate JSON field, `repository.full_name`, via `Handler#repository_name`: [3](#0-2) 

and `Repository.from_github_repo_name` splits that string on `/` to look up owner/name independently of `repository.owner.login`: [4](#0-3) 

Nothing ties `repository.full_name` back to the `repository.owner.login` (or `organization.login`) value that was used to select the verifying secret. An attacker who legitimately controls the webhook configuration for **one** organization ("Org A") registered in a multi-org Shipit deployment (`Shipit.github_organizations`) knows Org A's `webhook_secret` (they configured it on GitHub's side for their own org). They can sign an arbitrary JSON body with Org A's secret while setting:
- `repository.owner.login` = `"OrgA"` (or `organization.login` = `"OrgA"`) — satisfies `verify_signature`
- `repository.full_name` = `"OrgB/victim-repo"` — an entirely different organization's repository tracked by the same Shipit instance

This breaks the intended equality `organization_that_authenticated == organization_whose_repository_is_written`. The signature only proves "this came from someone who knows Org A's secret," not "this event concerns Org A's repositories."

### Impact Explanation
Depending on event type, the forged cross-org payload is processed by handlers that only trust `repository.full_name`:
- `push` → `PushHandler#process` enqueues `GithubSyncJob` with an attacker-chosen `expected_head_sha` for any not-archived stack matching the branch of `OrgB/victim-repo` [5](#0-4) . `GithubSyncJob` then fetches real commits from GitHub for that victim stack and appends them, potentially triggering deploy-eligibility changes.
- `status` → `StatusHandler#process` writes fabricated CI statuses (`create_status_from_github!`) onto arbitrary commits by SHA, independent of repository at all [6](#0-5) , which can flip a commit's deployability/CI gating for any stack that happens to reference that SHA.
- `check_suite` → schedules check-run refreshes on the victim stack's commits.
- `pull_request` handlers (opened/closed/labeled/etc.) create or archive review stacks for `OrgB` repositories based on the forged `repository.full_name`.

This crosses the "unauthorized ... deploy" boundary called out in the rules: an attacker who is only authorized (owns webhook config) for Org A can inject fabricated commit-status/CI-state and trigger sync/deploy-eligibility side effects for stacks belonging to Org B, which they have no authorization over. This matches the "organization that authenticated versus the repository that is written" trust-binding break named in the rules.

### Likelihood Explanation
Requires the Shipit deployment to be configured with multiple GitHub organizations (`Shipit.github_app_config`/multi-org secrets support, added per CHANGELOG "Support multiple GitHub organisations. (#1151)"), and the attacker to control the webhook secret of at least one of those configured organizations (i.e., they are legitimately allowed to send webhooks for Org A, but not Org B). This is a realistic multi-tenant scenario for a shared Shipit instance serving several orgs, and no privileged Shipit account, API token, or GitHub App private key is needed — only knowledge of one org's already-configured webhook secret, which is inherent to being the admin/maintainer of that org's GitHub webhook settings.

### Recommendation
In `verify_signature`, after determining `repository_owner` and validating the signature, re-derive the same "authenticating organization" from `repository.full_name`'s owner segment (or `organization.login`) and reject the request (422) if they disagree, or better, always verify using the org derived consistently from a single canonical field and have every `Handler` reject payloads whose `repository.full_name` owner doesn't match the organization whose secret produced a valid signature.

### Proof of Concept
1. Shipit configured with two orgs: `OrgA` (webhook_secret `sA`, attacker controls this org's GitHub webhook settings) and `OrgB` (secret `sB`, unrelated, hosts stack `OrgB/victim-repo`).
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...attacker-chosen-sha",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(sA, body)` using their own known `sA`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and verifies successfully against `sA` [1](#0-0) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` [3](#0-2)  and enqueues `GithubSyncJob` for the `OrgB` stack with the attacker-supplied `expected_head_sha`, even though the signature only proved knowledge of `OrgA`'s secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
