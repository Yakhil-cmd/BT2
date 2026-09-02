### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler` updates commit CI status by looking up commits **globally by SHA**, without restricting the lookup to the repository the inbound webhook actually belongs to. This breaks the binding `organization authenticated by the webhook signature == repository whose commits are written`, allowing an attacker who merely controls a repository/organization that has the Shipit GitHub App installed (and can therefore produce validly-signed webhooks for *their own* repo) to forge CI status updates on commits belonging to a completely unrelated repository/stack tracked by the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` only proves that a webhook was sent by the GitHub App installed on the organization identified by `repository_owner` (derived from the attacker-controlled payload) — it does not constrain *which repository's data the payload may mutate*: [1](#0-0) [2](#0-1) 

The base `Handler` class provides a `stacks` helper that correctly scopes work to the repository named in the payload: [3](#0-2) 

`PushHandler` uses this scoping correctly — it only touches stacks belonging to `Repository.from_github_repo_name(repository_name)`: [4](#0-3) 

`StatusHandler`, however, never calls `stacks`/`repository_name` at all. It resolves target commits purely by SHA across the entire database: [5](#0-4) 

Because GitHub's Status/Commit-Status API lets anyone with write access to a repository create a `status` event with an **arbitrary `sha` string** (it does not have to correspond to a real commit object in that repository), an attacker who has push/admin access to any repository that has the Shipit GitHub App installed can send a validly-signed `status` webhook whose `sha` field matches a commit SHA that exists only in a different, unrelated organization's repository tracked by the same Shipit deployment. `verify_signature` will pass (the signature is valid for the attacker's own org's app secret), but `Commit.where(sha: params.sha)` then updates the status of the victim commit in the victim repository, since the lookup carries no repository/stack scoping.

### Impact Explanation
Commit statuses drive Shipit's CI-gating and merge/deploy readiness logic (`Commit#create_status_from_github!`). An attacker who only controls an unrelated repository configured with the Shipit App can inject a fabricated "success" status onto a commit belonging to a different organization's stack, potentially causing that stack to treat an unvetted commit as CI-green and proceed with a deploy, rollback, or merge action it should not have taken. This crosses the required boundary of an unauthorized deploy/rollback/merge without needing any Shipit session, ApiClient token, or privileged account — only push access to some other repository that happens to be configured with the Shipit GitHub App.

### Likelihood Explanation
Moderate-to-high in any Shipit installation that manages multiple organizations/repositories under one deployment (the documented multi-org `github:` config format exists precisely to support this). Any contributor with push access to one managed repo, or any user who can trigger a `status` webhook there (e.g., via CI integrations they control), can exploit this without any additional privilege escalation.

### Recommendation
Scope the `StatusHandler` lookup to the repository named in the webhook payload, mirroring `PushHandler`/`Handler#stacks`, e.g. restrict `Commit.where(sha: params.sha)` to commits belonging to `Repository.from_github_repo_name(repository_name)`'s stacks before updating status.

### Proof of Concept
1. Attacker has push access to `attacker-org/some-repo`, which has the Shipit GitHub App installed (webhook signing configured for `attacker-org`).
2. Attacker uses the GitHub API (`POST /repos/attacker-org/some-repo/statuses/{sha}`) to create a status where `{sha}` is copied from a known commit belonging to `victim-org/victim-repo`, a repository tracked by the same Shipit instance under a different stack.
3. GitHub delivers a `status` webhook to Shipit, signed with `attacker-org`'s webhook secret.
4. `WebhooksController#verify_signature` succeeds because it only checks the signature against `attacker-org`'s configured secret.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, matches the victim commit in `victim-org/victim-repo`, and calls `create_status_from_github!`, updating that commit's CI status without any check that the webhook's repository matches the commit's repository.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
