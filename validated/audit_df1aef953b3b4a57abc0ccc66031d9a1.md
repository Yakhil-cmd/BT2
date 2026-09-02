### Title
Cross-repository forged commit status via unscoped SHA lookup in `StatusHandler` breaks the organization-authenticated vs. repository-written binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler` resolves the target `Commit` purely by SHA, with no check that the commit belongs to the repository/organization whose webhook signature was verified. In a multi-organization Shipit deployment (the engine explicitly supports configuring `github:` per-organization secrets, see `config/secrets.development.example.yml:18-38`), an actor who legitimately controls one configured GitHub organization/App can forge a valid webhook signature for that organization while pointing the `status` event payload at a commit SHA belonging to a completely different organization's repository, causing Shipit to write a forged `CommitStatus` onto that unrelated commit.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the incoming signature against using a value taken from the untrusted JSON payload itself: [1](#0-0) [2](#0-1) 

This is safe only if every downstream handler subsequently confirms that the entity being mutated actually belongs to the same repository/organization that was used to select the secret. The base `Handler` class does establish this binding correctly for most handlers, by scoping to the repository named in the payload: [3](#0-2) 

`PushHandler` and `CheckSuiteHandler` both use this `stacks` scope (derived from `repository.full_name`) before touching any commit: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, does not use `stacks`/`repository_name` at all — it looks up commits globally by SHA across the entire Shipit instance and writes a status to whatever it finds: [6](#0-5) 

The equality that should hold is:
`organization/App authenticated by verify_signature (repository_owner from payload)` == `organization owning the repository whose Commit is mutated by the handler`

For `StatusHandler` this equality is never checked. The signature only proves the payload was signed by *some* configured organization's secret (whichever `repository_owner`/`organization.login` the attacker put in the JSON body and which they legitimately control); it proves nothing about which commit/repository the `sha` field refers to.

### Impact Explanation
An attacker with legitimate control of any one GitHub organization/App configured in a multi-org Shipit instance can:
1. Craft a `status` event payload with `repository.owner.login` (or `organization.login`) set to their own org, correctly signed with their own known `webhook_secret`.
2. Set `sha` to a commit hash belonging to a stack owned by a different organization tracked by the same Shipit instance.
3. Have Shipit create a `CommitStatus` on that unrelated commit via `Commit#create_status_from_github!` — i.e., a cross-repository write performed without ever proving control over, or a valid signature for, the target repository's organization.

Commit statuses are consumed by Shipit's merge/deploy-safety gating (`Shipit::Status::Group`, `DeploySpec` required-status checks), so a forged "success" status can help make an unsafe or unreviewed commit appear deployable, which aligns with the "unauthorized deploy" impact class.

### Likelihood Explanation
This requires the attacker to already control a legitimate GitHub organization/App entry in the same shared Shipit installation (a real, but not privileged-to-Shipit, credential — they hold no Shipit session, API token, or admin right over the victim organization). Given that condition, exploitation is trivial: a single crafted HTTP POST to `/webhooks` with a correctly-signed body using the attacker's own secret. No collision or guessing is needed beyond knowing a target SHA, which is often public (open-source repos, PR pages, etc.).

### Recommendation
In `StatusHandler#process` (and any other handler that doesn't already go through `stacks`), scope the `Commit` lookup to the repository resolved from the verified payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently restrict via `Repository.from_github_repo_name(repository_name)`, so a commit can only be mutated if it belongs to the same repository that was used to select/verify the webhook signature.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `config/secrets.development.example.yml:18-38`).
2. As a member/owner of `org-a`'s GitHub App, compute a valid `X-Hub-Signature` for the following JSON body using `org-a`'s `webhook_secret`:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/some-repo" },
  "sha": "<commit sha belonging to a stack under org-b>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. POST this to `/webhooks` with header `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` as `org-a`, verifies successfully against `org-a`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the commit under `org-b`'s stack (since lookup is global, unscoped by `repository.full_name`), and creates a forged `success` status on it, even though the request was never authenticated for `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
