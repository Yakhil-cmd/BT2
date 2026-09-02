## Analysis

This confirms the binding-break: signature verification is keyed off `repository_owner` (org login used to select which GitHub App/secret verifies the HMAC), while every webhook handler resolves its target purely from `payload.dig('repository', 'full_name')` [1](#0-0) . The `verify_signature` before_action picks the app config via `repository_owner` [2](#0-1) , and `repository_owner` is read from `params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')` [3](#0-2) . In a multi-organization deployment (`Shipit.github(organization: ...)`, documented in `docs/setup.md` and `lib/shipit.rb#github`) each org has its own `webhook_secret` [4](#0-3) [5](#0-4) .

A member of Organization A knows (or controls) their own app's `webhook_secret` for A only (this is the normal, unprivileged trust boundary a multi-tenant Shipit install is supposed to enforce — org A's webhook credentials should only be able to affect org A's stacks). However nothing ties the HMAC-verifying identity (`repository.owner.login`) to the `repository.full_name` used by `PushHandler`, `CheckSuiteHandler`, `StatusHandler`, etc. An attacker who can trigger delivery of an org-A-signed webhook body (or simply POST directly to `/webhooks` since this endpoint has no additional authentication beyond the HMAC) can set `repository.owner.login = "A"` (so the signature check picks org A's `webhook_secret`, which the attacker knows) while setting `repository.full_name = "B/victim-repo"` (a stack belonging to organization B, tracked in Shipit under a different `github_app`). Because the signature is computed over the raw body with A's secret and A's secret is what the attacker possesses, `verify_webhook_signature` succeeds [6](#0-5) ; the handler then never re-checks that the acted-upon `full_name`'s owner matches the org that authenticated the request — it just calls `Repository.from_github_repo_name(repository_name)` and operates on whatever stack that resolves to [1](#0-0) .

This exactly matches the report's bug class ("a callback/field that the contract acts on is not the one covered by the verification") mapped onto the rule's named binding: *"an organization that authenticated versus the repository that is written."*

### Impact
`PushHandler` calling `stack.sync_github(expected_head_sha:)` on org B's stack, and `CheckSuiteHandler`/`StatusHandler` mutating commit statuses/check-runs for org B's commits, are triggered by a payload authenticated only as org A. This is a cross-organization/cross-repository write into another tenant's stack state (queuing sync jobs, injecting arbitrary commit statuses that CI-gate deploys, forging check-run refresh), which can influence or unblock an unauthorized deploy in another organization's Shipit tenant — satisfying the "cross-repository writes" / "unauthorized deploy" impact bar.

### Root cause
The `verify_signature` authentication step and the handlers' target-resolution step read two different fields of the same untrusted JSON body (`repository.owner.login` vs `repository.full_name`) without ever asserting they are consistent, and the HMAC itself provides no assurance that the *identity implied by which secret validated it* matches the *repository the payload claims to describe*.

---

### Title
Cross-organization webhook forgery via `repository.owner.login`/`repository.full_name` mismatch in multi-app Shipit deployments - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
In a multi-GitHub-App Shipit configuration, the webhook signature is verified against the `webhook_secret` chosen by `repository.owner.login` in the payload, but every webhook handler (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, etc.) resolves its target stack from the unrelated `repository.full_name` field. An attacker who legitimately possesses one organization's `webhook_secret` can forge a signed payload whose `owner.login` matches their own org (so verification passes) but whose `full_name`/commit SHA references another organization's repository/stack, causing Shipit to act on that other tenant's data.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` [7](#0-6) . Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the raw JSON `params`, and the base `Handler` class computes its target purely from `payload.dig('repository', 'full_name')` via `stacks`/`repository_name` [1](#0-0) . Neither the controller nor the handler cross-checks that the `owner.login` used for authentication matches the owner encoded in `full_name`. Concrete handlers using this unchecked binding include `PushHandler#process` (queues `sync_github` on stacks matched only by `full_name`+branch) [8](#0-7)  and `CheckSuiteHandler#process` (mutates check-run state for matched stacks) [9](#0-8) .

### Impact Explanation
An organization's own webhook secret — knowledge that is inherent to running a legitimate GitHub App integration for that org and not a privileged Shipit credential — can be reused to sign a payload describing a *different* organization's repository. This breaks the tenant isolation multi-app Shipit installs (`docs/setup.md` "Using Multiple Github Applications") are designed to provide, letting one org's webhook credentials trigger syncs, forged commit statuses (which can satisfy `ci.require` gates), or check-run updates against another org's stacks — a cross-repository/cross-tenant write that can affect deploy eligibility.

### Likelihood Explanation
Requires only the ability to send a crafted, appropriately-signed HTTP POST to the public `/webhooks` endpoint using a webhook secret the attacker's own organization legitimately possesses (no Shipit login, API token, or GitHub write access to the victim repo is needed). This is realistic specifically in the documented multi-organization deployment mode.

### Recommendation
When resolving handler targets, validate that the repository's owner (`payload.dig('repository','owner','login')`) matches the organization whose secret verified the signature, or better, bind the accepted `full_name`/owner directly to the `GitHubApp` instance that performed verification and reject events where they diverge.

### Proof of Concept
1. Deploy Shipit with the multi-org config format (`secrets.github.OrgA`, `secrets.github.OrgB`), each with its own `webhook_secret`.
2. As a user who knows `OrgA`'s `webhook_secret` (e.g., an OrgA maintainer with access to the GitHub App settings), craft a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Sign it with `OrgA`'s `webhook_secret` (`sha1=HMAC(webhook_secret, raw_body)`) and POST to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature` set accordingly.
4. `verify_signature` looks up `Shipit.github(organization: 'OrgA')` and succeeds because the signature was made with OrgA's real secret [2](#0-1) .
5. `PushHandler` resolves `Repository.from_github_repo_name('OrgB/victim-repo')` and calls `stack.sync_github` on OrgB's stack [1](#0-0) [8](#0-7) , despite the request only having been authenticated as OrgA.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
