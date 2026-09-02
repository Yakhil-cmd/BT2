**StatusHandler** raises the strongest analog to the FrankenDAO precision-loss bug: a trust binding is checked over one field (the webhook's authenticating organization/repository), while the write operation is actually scoped by a *different, unverified* field carried in the very same payload.

### Title
Cross-repository commit-status forgery via organization-scoped webhook signature not binding to `sha` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook by looking up the GitHub App/organization keyed off `repository.owner.login` (or `organization.login`) in the payload, and validating the HMAC signature of the **raw payload** against that organization's `webhook_secret`. [1](#0-0)  Because the signature covers the whole raw body, this itself is sound for the `push` event, where the handler scopes writes to stacks under `payload.dig('repository','full_name')`. [2](#0-1) 

However, `StatusHandler` (the `status` event) does not use `repository_name`/`stacks` scoping at all. It looks up commits **globally by `sha`** and attaches the status to every matching `Commit` record across the entire Shipit installation, regardless of which repository/organization that commit actually belongs to: [3](#0-2) 

### Finding Description
The equality that should hold is:
`organization whose webhook_secret authenticated the request == organization/repository whose data is mutated`

For `status` events this equality is broken. The webhook signature only proves the payload was signed with *some* configured organization's `webhook_secret` (selected via `repository.owner.login` in that same payload) — it says nothing about which `sha` is inside the payload being authorized to receive a status update for a *different* repository's commit. `StatusHandler#process` performs `Commit.where(sha: params.sha)`, a **global, cross-repository lookup**, with no `stack`/`repository` filter tying the write back to the organization that was actually verified. [3](#0-2) 

This is structurally the same class of bug as `getCommunityVotingPower`: a value computed/validated in one context (multiplier applied per-term / signature verified per-org) is then combined/used in a way that silently loses the binding that was supposed to hold end-to-end (division should apply to the combined sum / the mutation should be scoped to the same repo that was verified). Here, an attacker who controls (or has push access to) **any** low-value organization/repository that Shipit is configured to receive webhooks from — and thus can produce a validly-signed `status` webhook for that org — can supply an arbitrary `sha` value belonging to a **different, higher-value stack's repository** (SHAs are public, derivable from any public commit history) and inject a forged CI status (`success`/`failure`, `context`, `target_url`) onto that unrelated commit.

### Impact Explanation
Commit statuses directly gate deploy safety logic and the merge queue: `Stack#deployable?`/`MergeRequest::StatusChecker` rely on `Commit#statuses`/`required_statuses` to decide whether a commit can be deployed or a PR can be auto-merged. [4](#0-3)  By injecting a forged `success` status for `ci/...` required contexts on another repository's commit sha, an attacker owning an unrelated, low-privilege organization webhook could satisfy CI requirements and enable an unauthorized deploy or auto-merge on a stack they do not otherwise control, without holding a Shipit session, `ApiClient` token, or GitHub write access to the target repository.

### Likelihood Explanation
Requires only (a) Shipit being configured for multiple GitHub organizations/repositories (a documented, supported configuration — `config/secrets.*.yml` explicitly shows multi-org `github:` blocks [5](#0-4) ), and (b) the attacker being able to trigger a `status` webhook from any one of those configured orgs/repos (e.g., a repo they legitimately administer, or via a CI integration they control there) referencing a `sha` value from the target repository, which is public information. No secret from the target organization is needed.

### Recommendation
Scope `StatusHandler#process` (and any other handler that doesn't already use `Handler#stacks`) to only update commits belonging to the repository identified in the payload/verified for that request, e.g. filter through `stacks.joins(:commits).where(commits: { sha: params.sha })` instead of a bare `Commit.where(sha: ...)`, mirroring the `repository_name`-scoped lookup already used by `PushHandler`.

### Proof of Concept
1. Shipit is configured with two GitHub orgs: `victim-org` (holds the target high-value stack) and `attacker-org` (attacker has admin/webhook rights there), each with its own `webhook_secret`.
2. Attacker finds a commit `sha` in `victim-org/victim-repo` that is required by CI on a Shipit stack (`required_statuses`/merge queue).
3. Attacker sends a `status` webhook event to Shipit's webhook endpoint, signed with `attacker-org`'s `webhook_secret`, with body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/dummy"}, "sha": "<victim sha>", "state": "success", "context": "ci/circleci"}`.
4. `WebhooksController#verify_signature` resolves `repository_owner` → `attacker-org`, verifies the HMAC using `attacker-org`'s secret — succeeds. [6](#0-5) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim commit by sha (global lookup, no org/repo check), and creates a `success` status on it. [3](#0-2) 
6. The forged status satisfies `required_statuses` for the victim stack's deploy/merge-queue checks, enabling an unauthorized deploy/merge.

*Note: I was unable to fully verify within the available index whether any additional, uncited validation exists elsewhere in the request pipeline (e.g., a global before_action) that further restricts `Commit.where(sha:)` to the verified organization's repositories; if such a check exists outside the files inspected, it would need to be confirmed to fully close this finding.*

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

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
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
