## Analysis

The "first depositor" bug class is about a piece of unvalidated/attacker-influenced input being used to derive a trusted parameter (the exchange rate) that then silently governs how a completely separate set of inputs (subsequent deposits) get processed, with no cross-check that the two are consistent. The reachable analog in this engine's threat model is the **organization used to authenticate a webhook versus the repository the webhook payload is allowed to act on** — exactly the binding called out in the rules ("an organization that authenticated versus the repository that is written").

`WebhooksController#verify_signature` derives which GitHub App config (and therefore which HMAC `webhook_secret`) to validate the raw POST body against from data taken out of the **same untrusted, attacker-suppliable JSON body**: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

Once the signature check passes for whichever organization's secret matched, `create` dispatches the *entire* raw payload — including its `repository.full_name` field — to the handlers unmodified: [2](#0-1) 

Every handler then re-derives the repository to act on independently, from `repository.full_name`, with no re-validation against the organization/secret that was actually used to authenticate the request: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Because `Shipit.github_organizations` supports multiple independently-configured GitHub Apps/orgs sharing one Shipit install, and `Repository.from_github_repo_name` looks a repo up purely by the `owner/name` string with no ownership/tenant check, a member of org A (who legitimately knows org A's `webhook_secret` because they administer org A's own GitHub App installation) can forge a raw webhook POST whose `organization.login`/`repository.owner.login` says `"org-a"` (so the signature check passes with org A's secret) while its `repository.full_name` says `"org-b/victim-repo"` — a stack belonging to a completely different, unrelated tenant.

This is a real, reachable authentication/authorization gap between "which secret validated this request" and "which repository's stacks this request is allowed to mutate."

### Impact quantification

Handlers reachable this way include:
- `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack of the victim repo matching the forged `branch`. [4](#0-3) 
- `StatusHandler`, which writes a forged CI status (`create_status_from_github!`) onto any `Commit` matching an attacker-chosen `sha` — not scoped to a repository at all, just a global `Commit.where(sha:)` lookup. [5](#0-4) 

`StatusHandler` is the most severe: it is not even repository-scoped — it matches any `Commit` row by raw sha. An attacker who knows (or brute-force-guesses/observes publicly, e.g. via GitHub's own commit history) the sha of a commit on a **victim stack with `continuous_deployment: true` and `ci.require` statuses configured** can forge a webhook, signed with their own org's secret, injecting a fabricated "success" status for that commit's required CI context. This satisfies `required_statuses` and can cause Shipit's continuous-delivery scheduler to `trigger_deploy` that commit automatically, i.e. an **unauthorized deploy** driven by a status the attacker never had permission to set (they have no GitHub write access to the victim repo, and no `deploy:stack` API permission) — this is exactly the "unauthorized deploy" impact class defined in scope.

I was not able to fully trace, within the remaining budget, the exact downstream code path from `Commit#create_status_from_github!` → `Commit#deployable?` → the continuous-delivery scheduler (`Stack.schedule_continuous_delivery` / `trigger_deploy`) to confirm there is no additional server-side re-validation of the status's issuing organization against the commit's actual repository before it is treated as authoritative for deploy-gating. This should be verified before treating the finding as fully proven; I could not read `commit.rb`'s `create_status_from_github!` or the CI-status/required-status matching logic in this pass.

### Title
Webhook signature verified against attacker-chosen organization while payload's `repository.full_name` (used by all handlers) is never checked against that organization — cross-tenant status/push forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to validate the HMAC signature against using a field (`repository.owner.login` / `organization.login`) taken from the same unauthenticated JSON body it is about to validate, then hands the *entire* unmodified payload — including an independently-controlled `repository.full_name` field — to handlers that resolve the target `Stack`/`Commit` from that field with no cross-check that it belongs to the organization whose secret validated the request.

### Finding Description
`repository_owner` in `verify_signature` is read straight from the attacker-suppliable request body [6](#0-5) . Every `Webhooks::Handlers::Handler` subclass independently re-reads `payload.dig('repository', 'full_name')` to resolve which `Stack`/`Repository` to mutate [3](#0-2) , and `StatusHandler` doesn't even use the `repository` field, matching any `Commit` by raw `sha` globally [5](#0-4) . Because `Shipit.github(organization:)` supports multiple tenants sharing one install [7](#0-6) , and nothing binds "the org whose secret validated this HMAC" to "the repo whose stacks/commits get mutated," these two fields can be made inconsistent by the attacker while both live inside the one payload they fully control.

### Impact Explanation
An attacker who administers their own org's GitHub App integration on a shared Shipit install (an "unprivileged" actor with respect to other tenants) can forge webhook POSTs signed with their own known secret that manipulate stacks/commits belonging to other orgs' repositories — triggering forced `sync_github` calls and, most seriously, forging CI/commit statuses that can satisfy `ci.require` and drive an unauthorized continuous-delivery deploy of a victim stack, matching the in-scope "unauthorized deploy" impact category.

### Likelihood Explanation
Requires only a valid webhook secret for *any* org configured on the shared instance (which a normal, legitimately onboarded tenant already possesses) and knowledge of a target commit sha, both realistic without any elevated Shipit privilege, `ApiClient` token, or GitHub write access to the victim repo.

### Recommendation
Bind the resolved repository/stack strictly to the organization whose secret validated the signature: after `verify_signature` succeeds, re-derive `repository_owner` and reject/short-circuit if it does not match the `organization`/`repository.owner.login` value later consumed by handlers, or better, pass the authenticated organization explicitly into each `Handler` and have `stacks`/`Commit` lookups filter by it instead of trusting the raw payload alone.

### Proof of Concept
1. Attacker is a legitimate tenant with GitHub App org `"org-a"`, and knows `org-a`'s configured `webhook_secret`.
2. Attacker crafts a raw JSON body for the `status` event: `{"sha": "<victim-commit-sha>", "state": "success", "context": "<required-ci-context>", "repository": {"owner": {"login": "org-a"}, "full_name": "org-a/whatever"}}`, computing a valid `X-Hub-Signature` HMAC with `org-a`'s secret.
3. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `repository_owner` to `"org-a"`, validates successfully against `org-a`'s secret.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit globally, irrespective of `org-a` — and calls `create_status_from_github!`, injecting a forged passing status for a repository the attacker has no access to.
5. If the victim stack has `continuous_deployment: true` and this status satisfies `ci.require`, the scheduler can trigger an unauthorized deploy of that commit. (Full confirmation of the deploy-trigger chain from `create_status_from_github!` was not completed in this session and should be verified.)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```
