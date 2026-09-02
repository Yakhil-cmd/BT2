### Title
Cross-repository commit-status injection via unscoped `StatusHandler` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The GitHub `status` webhook handler resolves the target `Commit` purely by its SHA, without verifying that the SHA belongs to the repository/organization whose webhook secret authenticated the request. This breaks the intended binding "organization that authenticated == repository that is written," letting a user who legitimately controls any repository configured in this Shipit instance inject a status onto a commit belonging to a completely different, unrelated repository/stack.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate the request based on the *sender-controlled* payload field `repository.owner.login` (or `organization.login`), and simply checks the HMAC signature matches that organization's `webhook_secret`: [1](#0-0) 

This only proves "this event was really sent by GitHub for organization X's app installation." It says nothing about which `Commit` row the handler is allowed to mutate.

`StatusHandler#process` then looks up commits **globally by SHA only**, with no scoping to the repository that owns the webhook: [2](#0-1) 

Contrast this with `CheckSuiteHandler`, which correctly scopes the lookup to the stacks that belong to the authenticated repository (`stacks` is derived from `payload.dig('repository','full_name')` in the base `Handler`) before touching any commit: [3](#0-2) [4](#0-3) 

`StatusHandler` never calls `stacks`/`repository_name` at all — it is missing the equivalent scoping that its sibling handler applies, so `Commit.where(sha: params.sha)` can match a `Commit` row belonging to *any* stack/repository tracked anywhere in the Shipit installation, not just the repository that owns the webhook's signing secret.

**Binding broken:** `organization_that_authenticated(webhook) == repository_that_is_written(commit.stack.repository)` — before the attacker's request this holds (GitHub only delivers `status` events for events happening in repos under an org's own installation); after a crafted-but-legitimately-signed `status` event from an attacker-controlled repository whose SHA happens to collide with (or is chosen to equal) a SHA tracked in a victim stack, the equality no longer holds — a status write lands on the victim's `Commit`.

### Impact Explanation
GitHub's Create-Commit-Status API does not require the referenced SHA to exist as a real commit in the calling repository, so a user with ordinary push/write access to any GitHub repository/org configured as a Shipit tenant can create a `status` event carrying an arbitrary 40-character SHA value and an arbitrary `state`/`context` (e.g., forging a `success` state). Because `StatusHandler` performs no repository-ownership check, this write lands on `Commit#create_status_from_github!` for the matching SHA in whichever stack owns that commit, `app/models/shipit/commit.rb`, regardless of which organization/repository the commit actually belongs to. Since Shipit's continuous-delivery/merge-queue readiness and required-status logic (`app/models/shipit/commit_checks.rb`, `app/models/shipit/stack.rb`) consume these `Status` rows to decide whether a commit is deployable, an attacker with only push access to an unrelated, low-trust repository can spoof a passing CI status on a victim stack's commit and influence/trigger an unauthorized deploy — a cross-repository write into another tenant's deploy-gating state.

### Likelihood Explanation
Requires only ordinary write/push access (or ability to trigger a `status` webhook) on any single repository that this Shipit instance is configured to receive webhooks for — not an ApiClient token, not a privileged Shipit account, and no compromise of `webhook_secret`. In a multi-tenant Shipit deployment (multiple `github:` orgs configured, as shown in `config/secrets.development.shopify.yml`) this is directly reachable by any tenant against any other tenant's stacks, making likelihood non-trivial.

### Recommendation
Scope `StatusHandler#process` to the requesting repository the same way `CheckSuiteHandler` and the base `Handler#stacks` do: restrict the `Commit` lookup to commits belonging to `stacks` (derived from `payload.dig('repository','full_name')`) instead of a bare `Commit.where(sha: params.sha)` over the entire commits table.

### Proof of Concept
1. Attacker has ordinary push access to `attacker-org/throwaway-repo`, which is configured (or auto-registered) in the target Shipit instance.
2. Attacker learns/guesses the SHA of a commit tracked by a victim stack (`victim-org/prod-repo`), e.g. from Shipit's public deploy history UI or GitHub commit list.
3. Attacker calls GitHub's `POST /repos/attacker-org/throwaway-repo/statuses/{victim_sha}` with `state: success`. GitHub does not validate the SHA belongs to `throwaway-repo`, and delivers a genuinely GitHub-signed `status` webhook (signed with `attacker-org`'s configured `webhook_secret`) to Shipit's `/webhooks` endpoint.
4. `WebhooksController#verify_signature` succeeds (valid signature for `attacker-org`) at `app/controllers/shipit/webhooks_controller.rb:24-49`.
5. `StatusHandler#process` runs `Commit.where(sha: victim_sha)` at `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`, finds the victim's commit in `prod-repo`, and records the forged `success` status against it — with no check that `attacker-org` has anything to do with `victim-org/prod-repo`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
