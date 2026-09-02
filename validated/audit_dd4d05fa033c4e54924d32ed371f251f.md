### Title
Cross-Organization Webhook Impersonation via Unbound `repository.owner.login` vs `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC validation based on `repository.owner.login` (or `organization.login`), while the actual event handlers (e.g. `PushHandler`, and other subclasses of `Handler`) resolve the *target* stack/repository using a completely different field, `repository.full_name`. Nothing in the code cross-checks that these two fields refer to the same organization. This breaks the trust equality: `organization authenticated (repository.owner.login)` == `repository actually written to (repository.full_name)`.

### Finding Description
`verify_signature` computes the signing organization purely from attacker-suppliable JSON fields: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GithubApp`/`GithubOrganizationHandler` instance configured for that specific org, and `verify_webhook_signature` checks the raw POST body's HMAC against *that org's* `webhook_secret`: [3](#0-2) 

If verification succeeds, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-controlled JSON body to the handlers. Every `Handler` subclass (e.g. `PushHandler`) resolves the target repository/stacks from a *different* field, `repository.full_name`, with no re-check that it belongs to the organization that produced a valid signature: [4](#0-3) [5](#0-4) 

Because Shipit is multi-tenant (it stores a webhook secret per configured GitHub organization, keyed by `organization.downcase` in the token cache and by `@organization` in `GithubApp`), an attacker who legitimately controls their own onboarded organization (and therefore knows/controls that organization's `webhook_secret`) can craft a payload where:
- `repository.owner.login` (or `organization.login`) = `"attacker-org"` — used only to select and pass HMAC verification with the attacker's own known secret.
- `repository.full_name` = `"victim-org/victim-repo"` — used by the handler to pick the real target stack.

The signature is valid (it was computed over the attacker's own crafted bytes using the attacker's own secret), yet the handler acts on a victim repository the attacker does not control on GitHub.

### Impact Explanation
This lets an unprivileged party (who has never been granted write access to the victim repository, an API token, or Shipit session) inject forged GitHub events against an arbitrary registered stack:
- `PushHandler` can force `sync_github` with an attacker-chosen `expected_head_sha` on a victim stack.
- Other handlers reachable through the same `Handler#repository_name` binding (e.g. status-related handlers) populate the `Status`/`CheckRun` records that `MergeRequest::StatusChecker` and the merge queue rely on to decide whether required CI has passed (`any_status_checks_failed?`, `any_status_checks_missing?`), per `app/models/shipit/merge_request.rb`: [6](#0-5) 
Forged/faked commit statuses for a victim's commits can make `reject_unless_mergeable!` pass unmerited, enabling an unauthorized automatic merge or unblocking a deploy checklist — matching the "unauthorized deploy, rollback or merge" impact category.

### Likelihood Explanation
Requires only that the attacker's own organization is a legitimately configured Shipit-integrated GitHub org (something any customer/tenant onboarding to a multi-org Shipit deployment can arrange), no privileged Shipit account, API token, or GitHub write access to the victim repo is needed. The only skill required is crafting a raw JSON body and computing its own valid HMAC signature, both of which are attacker-controlled.

### Recommendation
In `Shipit::WebhooksController`, after `verify_signature` succeeds, assert that `repository_owner` equals the owner segment of `repository.full_name` (and equals the resolved `Stack`/`Repository`'s actual owner in Shipit's database) before dispatching to handlers. Alternatively, resolve the signing organization from the already-loaded `Repository`/`Stack` record (looked up by `full_name`) rather than from a second, independently attacker-supplied field.

### Proof of Concept
1. Attacker onboards `attacker-org` to the Shipit instance (multi-org deployment) and knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(attacker-org secret, body)>` and POSTs to `/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC check succeeds (it's the attacker's own secret over the attacker's own bytes).
5. `PushHandler.call(params)` runs `stacks` → `Repository.from_github_repo_name("victim-org/victim-repo")` → triggers `sync_github(expected_head_sha: ...)` on the victim's stack, despite the attacker never having been authenticated as, or granted access to, `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
