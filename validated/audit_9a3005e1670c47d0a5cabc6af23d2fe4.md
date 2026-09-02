### Title
Webhook organization authentication is not bound to the repository the event acts on, allowing cross-organization forged webhooks - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate an inbound webhook using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). [1](#0-0) [2](#0-1) 

Every event handler, however, resolves the actual repository/stack acted upon from a completely separate JSON field, `payload.dig('repository', 'full_name')`, via `Handler#stacks`/`#repository_name`, without ever re-checking that `full_name` is consistent with the `repository.owner.login` that was cryptographically verified. [3](#0-2) 

This is the same handler base class used by the push, pull_request (opened/closed/labeled/etc.), status, membership and check_suite handlers registered in `Shipit::Webhooks.default_handlers`. [4](#0-3) [5](#0-4) 

### Finding Description
The binding that should hold is: `organization authenticated == organization of repository written`. In this engine that equality is never enforced.

`Shipit.github(organization: repository_owner)` looks up per-organization GitHub App config (potentially one of several, per `config/secrets.*.yml` multi-org examples) and `verify_webhook_signature` HMAC-validates the raw payload against that org's `webhook_secret`. [6](#0-5) [7](#0-6) 

Because `verify_signature` only proves "this raw body was signed with OrgA's secret", and the handler layer independently trusts `repository.full_name` (a second, unrelated field in the very same attacker-supplied JSON body) to pick which `Stack`/`Repository` the event applies to, an attacker who controls OrgA's webhook secret (e.g., an org admin who legitimately manages the GitHub App installation/webhook config for their own, unprivileged organization) can craft a payload where `repository.owner.login == "orgA"` (so the signature check passes) but `repository.full_name == "orgB/some-repo"` (an entirely different organization's repository configured on the same Shipit instance). The handler will act on `orgB/some-repo` using a signature that only proves authorization for `orgA`.

Additionally, `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for the resolved org: `return true unless webhook_secret`. [8](#0-7) 
If any org configured on the instance has no `webhook_secret` set (shown as an allowed/nil value in the setup examples), an unauthenticated caller can pick that org as `repository.owner.login` to trivially pass `verify_signature`, then set `repository.full_name` to any other org's repository to forge fully unauthenticated events for it — with no secret knowledge required at all. [9](#0-8) 

### Impact Explanation
Forged cross-organization events reach real handlers that mutate state tied to the target repository: e.g. `PullRequest::ClosedHandler#process` resolves `repository` purely from `params.repository.full_name` and calls `review_stack.archive!` on that repository's review stack, and `PushHandler`/`StatusHandler`/`CheckSuiteHandler` similarly key off `full_name` to enqueue sync/status-refresh jobs and update commit state that downstream feeds merge-queue and deploy eligibility decisions (`ci.require`, merge status, "target branch" head tracking). This crosses the "repository written" boundary the organization-scoped webhook secret is supposed to enforce, matching the required High/Critical impact class of cross-repository writes / unauthorized state changes affecting a repository the caller was never authorized for.

### Likelihood Explanation
Requires either (a) control of a valid `webhook_secret` for at least one organization configured on the Shipit instance — realistic for a self-service or multi-tenant setup where each org's own GitHub App admin can view/rotate that secret in GitHub, or (b) any organization on the instance left with `webhook_secret` unset, which the documented config format explicitly allows (`webhook_secret: # nil`). Either condition is plausible in the documented multi-organization deployment pattern (`config/secrets.development.shopify.yml`).

### Recommendation
In `Handler#repository_name`/`#stacks`, cross-validate that the resolved `repository.full_name`'s owner segment matches the `repository.owner.login` (or `organization.login`) that `WebhooksController#verify_signature` used to select the GitHub App/secret, and reject the event otherwise. Consider passing the verified organization explicitly into each handler rather than re-deriving it from unauthenticated payload fields.

### Proof of Concept
1. Configure two orgs in `secrets.yml`, `orgA` (attacker-controlled webhook secret known to attacker) and `orgB` (victim, has a Shipit stack).
2. POST to `/webhooks` with header `X-Github-Event: pull_request`, body:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": { "id": 1, "number": 1, "url": "...", "title": "x", "state": "closed",
    "additions": 0, "deletions": 0,
    "head": { "sha": "deadbeef", "ref": "refs/heads/x" },
    "user": { "login": "attacker" }, "assignees": [], "labels": [] },
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
  "sender": { "login": "attacker" }
}
```
3. Sign the raw body with `orgA`'s `webhook_secret` and send it as `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: "orgA")` and validates successfully.
5. `PullRequest::ClosedHandler` resolves `repository` from `params.repository.full_name` = `"orgB/victim-repo"` and archives/mutates the `orgB` review stack, despite the signature only proving authorization for `orgA`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```
