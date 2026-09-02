### Title
Forged GitHub Status webhook writes CI state onto commits in unrelated stacks/repositories - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler` updates `Commit` records by matching only the git `sha` from the incoming webhook payload, without ever re-validating that the commit's owning repository/stack corresponds to the GitHub organization whose `webhook_secret` was used to authenticate the request. Every other event handler (`PushHandler`, `CheckSuiteHandler`) scopes its side effects through `Repository.from_github_repo_name(payload['repository']['full_name'])` before acting, but `StatusHandler` does not, breaking the binding "organization authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to HMAC-verify the raw payload against using a field taken from the unverified JSON body itself: [1](#0-0) [2](#0-1) 

This proves only that the request was legitimately signed *for some particular GitHub organization/app installation* (`Shipit.github(organization: repository_owner)`), each of which can have its own independent `webhook_secret` in a multi-org Shipit deployment: [3](#0-2) 

Once the signature check passes, the handler dispatched for the `status` event is `StatusHandler`, which looks up commits **globally by SHA**, with no scoping to the repository/organization that produced the valid signature: [4](#0-3) 

Contrast this with the base `Handler` class' `stacks` helper, which other handlers (`PushHandler`, `CheckSuiteHandler`) explicitly call to scope their effects to the repository named in the payload: [5](#0-4) [6](#0-5) [7](#0-6) 

`StatusHandler` never calls `stacks`/`repository_name` at all — it is the only handler that acts purely on an attacker-influenced content field (`sha`) with no cross-check against the identity that was cryptographically verified.

Git SHAs are content-addressed but not globally unique to a single repository: identical trees/parents/commit metadata (e.g. an initial empty commit, a cherry-picked commit, a mirrored/forked repository, or a deliberately crafted commit with matching author/committer/timestamp/tree/parent) can produce the same SHA in two unrelated repositories that are both tracked as separate Shipit stacks (each configured under a different GitHub organization with a different `webhook_secret`, as shown in the multi-org setup docs).

### Impact Explanation
An attacker who can trigger a legitimately-signed `status` webhook for **any one** GitHub organization/repository configured in the Shipit instance (e.g. by pushing a commit status via the GitHub API to a repo they control, which is itself onboarded onto the same Shipit instance) can cause `Commit#create_status_from_github!` to be invoked for **any other stack's commit** that happens to share that SHA — a cross-repository write of CI state. Since `shipit.yml`'s `ci.require` gates whether a deploy is allowed to run, forging a "success" status onto a commit belonging to a repository/stack the attacker has no access to can be used to unblock or influence deploy eligibility in a stack outside the attacker's trust boundary. This matches the "cross-repository writes" High/Critical impact category.

### Likelihood Explanation
Medium: the attacker needs (a) legitimate ability to send a validly-signed `status` webhook for at least one org/repo hosted on the target Shipit instance (achievable by any contributor with API/webhook access to their own low-privilege repo in a multi-tenant Shipit deployment), and (b) a SHA collision with a commit in the victim stack, which is realistic for content-identical commits (e.g., initial/empty commits, mirrored repositories, or repositories seeded from the same template) rather than requiring a SHA-1 cryptographic break.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: restrict the `Commit` lookup to commits belonging to `stacks` (i.e., `Repository.from_github_repo_name(payload.dig('repository','full_name'))`), so that a status update can only be applied to commits within the repository that was actually authenticated for that webhook delivery.

### Proof of Concept
1. Shipit instance is configured with two GitHub organizations, `OrgA` and `OrgB`, each with its own `github.webhook_secret` (per `docs/setup.md` multi-org config), both tracking separate stacks.
2. Attacker controls a repository under `OrgA` (or has committer access there) and pushes a commit whose SHA is engineered/known to be identical to a commit that already exists in an `OrgB` stack (e.g., both start from the same empty-tree initial commit, or the commit is cherry-picked with identical metadata).
3. Attacker triggers (or GitHub naturally sends) a `status` event for that SHA from `OrgA`, signed with `OrgA`'s `webhook_secret`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `OrgA` and verifies successfully against `OrgA`'s secret.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, which matches the commit row belonging to the `OrgB` stack, and calls `commit.create_status_from_github!(params)`, writing attacker-chosen `state`/`context`/`description` onto a commit in a repository the attacker never proved access to.

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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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
