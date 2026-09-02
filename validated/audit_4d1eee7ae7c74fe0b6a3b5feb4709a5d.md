### Title
Webhook `status` events are not scoped to the authenticated repository, allowing cross-repository CI status forgery — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` binds a webhook's cryptographic validity to a *GitHub organization* derived from the payload (`repository.owner.login` / `organization.login`), and picks that org's `GitHub App`/`webhook_secret` to verify against. [1](#0-0)  Every other event handler that mutates state re-derives the *target repository* from the payload's `repository.full_name` field via `Handler#repository_name`/`#stacks`, so the entity being verified (the org) and the entity being written to (the repository/stack) stay bound together. [2](#0-1)  `StatusHandler`, however, breaks that binding: it never consults `repository`/`stacks` at all, and instead looks up commits system-wide purely by SHA and writes a status onto every match. [3](#0-2) 

### Finding Description
The equality that should hold for every mutating webhook handler is:

`organization that authenticated the request == repository/stack that gets written`

`PushHandler` (and other handlers that inherit `Handler#stacks`) preserve this: they scope all writes to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, i.e., exactly the repository whose owning org's secret was used in `verify_signature`. [2](#0-1)  `MembershipHandler` similarly keys its writes off `params.organization.login`, the same field used for signature-org selection. [4](#0-3) 

`StatusHandler` does not inherit or use this scoping at all:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`Commit.where(sha: params.sha)` queries the entire `Commit` table for the whole Shipit installation — across every `Repository`/`Stack` that has ever synced that SHA — with no filter tying the lookup back to the `repository` (or `owner`/`organization`) field that `verify_signature` used to select the signing secret. [5](#0-4)  Shipit is explicitly designed to be multi-tenant: `config/secrets.development.shopify.yml` and the setup docs show multiple independent GitHub orgs/apps (each with its own `webhook_secret`) configured in a single Shipit instance. [6](#0-5)  Because `verify_signature` only proves "this payload came from *some* org whose secret matches," and `StatusHandler` never checks that the commit it's updating actually belongs to that org's repository, a payload validly signed by Org A's webhook secret can write a CI status onto a `Commit` row that belongs to Org B's stack, as long as the two share an identical commit SHA (a very common occurrence for forked/mirrored/vendored repositories, since a git SHA is a hash of tree+parents+author/committer metadata+message and is trivially reproducible by anyone who can see that public metadata, e.g. via the GitHub API).

### Impact Explanation
`Commit#state`/`#deployable?` is driven by the recorded `Status` rows (see the CI-gating tests in `test/models/commits_test.rb`, which rely on `statuses` to compute `deployable?`). [7](#0-6)  If an attacker who legitimately controls (or has push access to) one org's repository onboarded to a multi-tenant Shipit instance can trigger a genuinely signed `status` webhook for a SHA that also exists as a tracked commit in a *different* org's stack, they can inject a fabricated `success` status for a required CI context on that unrelated repository's commit. Since deploy gating (`ci.require`, `deployable?`) is based on these statuses, this can make an otherwise CI-failing/untested commit in a victim's stack appear deployable, leading to an unauthorized deploy — a Critical-severity outcome per the ruleset ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitation requires: (1) the attacker controls or can trigger webhooks for at least one org/repository configured in the same multi-tenant Shipit instance (a legitimate, low-privilege position relative to the victim stack — no Shipit session, `ApiClient`, or victim-repo write access needed), and (2) a shared commit SHA between the attacker's repo and the victim's tracked stack — realistic for forks, mirrors, or vendored dependencies, and otherwise reproducible since git SHAs are derived from fully public metadata. No credential of the victim org is needed; only the attacker's own valid webhook signature, which they already legitimately possess for their own onboarded repository.

### Recommendation
Scope `StatusHandler#process` (and any other handler that writes based on payload data) to the repository identified by `payload.dig('repository', 'full_name')`, mirroring `Handler#stacks`/`#repository_name`, e.g. restrict the `Commit.where(sha: params.sha)` lookup to `commits.joins(:stack).where(stacks: { repository_id: repository.id })` (or equivalent), so that a webhook can only mutate commits that belong to the same repository/org whose secret authenticated it.

### Proof of Concept
1. Shipit is configured (per `config/secrets.development.shopify.yml`) with two orgs, `somegithuborg` and `someothergithuborg`, each with its own `github.webhook_secret`. [6](#0-5) 
2. Attacker has legitimate push access to a repository under `somegithuborg` that is also onboarded as a Shipit stack, and knows/controls that org's `webhook_secret` delivery (i.e., can produce a validly-signed `status` event for that org, e.g. by simply having GitHub deliver a real webhook, or by controlling the repo enough to trigger one).
3. Attacker crafts (or has GitHub naturally deliver) a `status` event payload where `sha` equals a commit SHA that is also tracked as part of a `Stack` belonging to `someothergithuborg` (e.g., via a forked/mirrored commit with identical metadata), and `state` = `"success"`, `context` = the required CI context for the victim stack.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `somegithuborg` from the payload and successfully verifies the signature using `somegithuborg`'s secret. [8](#0-7) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no repository filter, finds the matching `Commit` under the `someothergithuborg` stack, and calls `commit.create_status_from_github!(params)`, writing the forged "success" status onto a commit outside the authenticated org. [3](#0-2) 
6. The victim stack's commit now satisfies `ci.require`, becoming deployable/eligible for continuous deployment despite never having a real passing CI run for that context.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L6-21)
```ruby
      class MembershipHandler < Handler
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
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

**File:** test/models/commits_test.rb (L554-578)
```ruby
    test "#deployable? is true if commit status is 'success'" do
      assert_predicate shipit_commits(:cyclimse_first), :deployable?
    end

    test "#deployable? is true if stack is set to 'ignore_ci'" do
      commit = shipit_commits(:first)
      commit.stack.update!(ignore_ci: true)
      assert_predicate commit, :deployable?
    end

    test "#deployable? is false if commit has no statuses" do
      refute_predicate shipit_commits(:fifth), :deployable?
    end

    test "#deployable? is false if commit is locked" do
      commit = shipit_commits(:cyclimse_first)
      commit.update!(locked: true)
      refute_predicate commit, :deployable?
    end

    test "#deployable? is false if a required status is missing" do
      commit = shipit_commits(:cyclimse_first)
      commit.stack.stubs(:required_statuses).returns(%w[ci/very-important])
      refute_predicate commit, :deployable?
    end
```
