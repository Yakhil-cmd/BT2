### Title
Cross-repository CI status forgery via unscoped `StatusHandler` webhook write - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates an inbound GitHub webhook against the GitHub App/organization named in the payload's `repository.owner.login` [1](#0-0) [2](#0-1) . However, once verified, `Shipit::Webhooks::Handlers::StatusHandler#process` writes a CI status onto **any** `Commit` in the entire Shipit database that matches the payload's `sha`, with no check that the commit belongs to a stack whose repository/organization matches the one that was actually authenticated [3](#0-2) . This breaks the binding "organization authenticated == repository written."

### Finding Description
Compare `StatusHandler` to its sibling handlers, `PushHandler` and `CheckSuiteHandler`, both of which correctly scope database writes to the `stacks` collection (which is itself scoped to the authenticated repository via the `Handler` base class):

- `PushHandler#process` restricts to `stacks.not_archived.where(branch:)` before syncing [4](#0-3) .
- `CheckSuiteHandler#process` restricts to `stacks.where(branch: ...)` then `stack.commits.where(sha: ...)` [5](#0-4) .
- `StatusHandler#process` instead queries the global `Commit` model directly: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — no reference to `stacks` at all [3](#0-2) .

Because `Commit` records across *all* stacks (all organizations/repositories configured in the Shipit instance) are matched purely on `sha` string equality, a payload that is signature-verified for organization A can still mutate `Status` rows attached to commits that belong to stacks under organization B, as long as a `Commit.sha` collision exists between the two. Git commit SHA-1 hashes are fully deterministic from tree hash, parent(s), author, committer (including timestamps), and message — all of which are visible in any public git history. An attacker who can read a target commit's metadata can reproduce an identical commit object (and thus an identical SHA) inside a repository they control, then trigger a legitimately GitHub-signed `status` event for that SHA from their own repo/organization.

The equality that should hold but doesn't:
`organization that signed/authenticated the webhook == repository whose Commit/Status rows get written`

`verify_signature` enforces the left side; `StatusHandler#process` never enforces the right side.

### Impact Explanation
CI/status state gates merge-queue eligibility (`merge.require`, `ci.require`, `ci.blocking`) and deploy eligibility (`Commit#deployable?`) for every stack in the Shipit install. By forging a `success` status for a required context on a *different* organization's commit, an attacker who only controls a repository/org unrelated to the victim (but installed on the same Shipit deployment) can make an unreviewed/never-CI-passed commit appear deployable or mergeable in the victim's stack — an unauthorized deploy/merge and a cross-repository (actually cross-organization) database write, both explicitly in-scope Critical/High impacts.

### Likelihood Explanation
The only prerequisite is the ability to push a specially crafted commit (with matching tree/parent/author/committer/message metadata reproduced from a public target commit) to a repository under any organization onto which the Shipit GitHub App is installed, and to have GitHub deliver a `status` webhook for it (e.g. via a CI integration or the GitHub Status API). No knowledge of the webhook secret, no Shipit session, ApiClient token, or privileged Shipit account is required — this is purely an unprivileged cross-tenant write via a correctly-signed webhook for an unrelated repository.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve target commits only through `stacks` (repository-scoped) rather than the global `Commit` table, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))`, or restrict lookups to `Commit.where(sha: params.sha, stack: stacks)` where `stacks` is derived from the authenticated `repository_owner`/repository payload.

### Proof of Concept
1. Identify (or clone) a Shipit instance configured with multiple GitHub organizations/Apps (as documented in `config/secrets.development.shopify.yml`) [6](#0-5) , tracking a victim stack under org `victim-org/app`.
2. As an attacker, create a repository under a different organization `attacker-org/decoy` that has its own Shipit-installed GitHub App with a webhook secret you legitimately possess (because it's your own app installation).
3. Fetch the public git objects (tree, parents, author, committer, message) of a target commit in `victim-org/app` and reconstruct an identical commit object in `attacker-org/decoy`, producing an identical SHA-1.
4. Trigger (or directly send, since you control the app/secret) a `status` webhook event with that `sha` and `state: success`, `context: <the context required by victim-org/app's merge/ci gating>`.
5. `WebhooksController#verify_signature` succeeds because the signature is valid for `attacker-org` [7](#0-6) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matches the colliding-SHA commit belonging to `victim-org/app`'s stack, and calls `create_status_from_github!`, marking it CI-passing in the victim's stack despite the attacker having no relationship to `victim-org` [3](#0-2) .

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
