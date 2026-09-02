I have enough context to finalize the analysis.

### Title
Cross-organization webhook signature confusion allows forging commit statuses to unblock deploys/merges of a repository not owned by the attacker's GitHub App - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for HMAC verification based on an **untrusted field taken from the very payload being verified** (`repository_owner`, derived from `repository.owner.login` or `organization.login`), rather than from anything cryptographically bound to the signing app. `Shipit::Webhooks::Handlers::StatusHandler#process`, which actually writes data, resolves the target `Commit` using a **different field from the same payload** (`sha`) with no scoping to the organization/app that was used to authenticate the request. This breaks the intended equality "organization whose secret authenticated the request == repository/commit the request is allowed to write to."

### Finding Description
`verify_signature` computes:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` resolves a per-organization `GitHubApp` instance whose `webhook_secret` is configured independently per organization, as documented for multi-org installs: [2](#0-1) 

The secret used to verify the HMAC is therefore chosen from a value inside the unverified payload itself. Anyone who legitimately administers a GitHub App for *any* organization configured in Shipit (e.g. their own `OrgA`, which they control and for which they know `webhook_secret`) can HMAC-sign an arbitrary JSON body with `OrgA`'s secret while setting `repository.owner.login` to `"OrgA"` so `verify_signature` looks up and validates against `OrgA`'s secret — passing verification regardless of what other fields in the body claim.

Once verification passes, `WebhooksController#create` dispatches to event handlers using the same untrusted `params`: [3](#0-2) 

For the `status` event, `StatusHandler#process` performs:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

This lookup is **global across the whole Shipit instance** — it is not scoped by `repository.owner.login`/`repository.full_name`, nor by the organization whose secret was used to authenticate the request. A commit SHA is effectively public information (visible in git history, PRs, CI logs). So an attacker who controls a legitimate `OrgA` GitHub App can forge a `status` webhook, sign it with `OrgA`'s secret, but target a `sha` that belongs to a completely different stack owned by `OrgB` — an organization/repository the attacker has no access to.

Commit statuses directly gate deploy and merge decisions: `Commit#deployable?` requires `success? && !blocked?` based on statuses, and `blocked?`/`blocking?` are derived from the same status table: [5](#0-4) 
Merge-queue readiness (`MergeRequest#reject_unless_mergeable!`, `all_status_checks_passed?`, etc.) and CI gating documented in `ci.require`/`merge.require` also rely on these forged status rows: [6](#0-5) 

### Impact Explanation
This crosses the "organization authenticated versus repository written" boundary explicitly called out as in-scope: the signature check authenticates against `OrgA`, but the actual write (`Commit#create_status_from_github!`) lands on a commit belonging to `OrgB`'s repository/stack. By injecting a fabricated `success` status for a required/blocking CI context, an attacker can flip `Commit#deployable?` to `true` for a victim organization's commit, unblocking `next_commit_to_deploy`/`trigger_continuous_delivery` and enabling an unauthorized deploy, or clearing merge-queue CI requirements (`ci_missing`/`ci_failing` rejections) to enable an unauthorized merge — without ever having credentials for `OrgB`. This matches the "unauthorized deploy, rollback, or merge" High-impact category.

### Likelihood Explanation
Requires only that the attacker legitimately controls (or has purchased/registered) a GitHub App/organization that is one of the configured organizations in the target Shipit instance's multi-org `github:` config — a scenario Shipit explicitly documents and supports (any organization is allowed to install/onboard its own app). No access to the victim organization, its repository, or its webhook secret is needed; only the target commit's SHA, which is not secret.

### Recommendation
Do not select the verification secret from unauthenticated payload fields. Instead:
- Verify the webhook signature against every configured organization's secret (or a global secret) rather than one chosen from the payload, or
- After successful signature verification, re-derive and enforce that all repository/commit lookups performed by the corresponding handler are scoped to the same organization (`repository.owner.login`) that matched the verified secret, rejecting/ignoring records that belong to a different owner (e.g., scope `StatusHandler`'s `Commit.where(sha:)` by `stacks.repository.owner == repository_owner`).

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled GitHub App, secret known to attacker) and `OrgB` (victim, unrelated secret), per the documented multi-app config [2](#0-1) .
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<victim commit sha belonging to OrgB's stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner == "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully [7](#0-6) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the victim's OrgB commit — and calls `create_status_from_github!`, injecting a forged `success` status [4](#0-3) .
6. The victim's commit now reports the forged status, which can flip `Commit#deployable?` to `true` [8](#0-7)  or clear merge-queue CI requirements, enabling an unauthorized deploy or merge on OrgB's stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** docs/setup.md (L182-209)
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

**File:** app/models/shipit/commit.rb (L219-237)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** README.md (L444-465)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
  require:
    - ci/circleci
```

**<code>ci.hide</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to ignore.

For example:
```yml
ci:
  hide:
    - ci/circleci
```

**<code>ci.allow_failures</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to be visible but not to required for deploy.

```
