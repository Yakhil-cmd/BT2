### Title
Cross-org `owner/full_name` split lets an attacker forge a `pull_request` webhook that archives a victim org's review stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against based solely on `repository.owner.login` (or `organization.login`), while every `pull_request` handler resolves the mutated `Repository`/`ReviewStack` from `repository.full_name` [1](#0-0) [2](#0-1) [3](#0-2) . These two fields are never checked for consistency, and `verify_webhook_signature` short-circuits to `true` whenever the selected org has no `webhook_secret` configured [4](#0-3) , letting an attacker verify under a no-secret org while mutating a different, victim org's repository.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces: `repository_owner` (used to pick the signing org) `==` `owner(repository.full_name)` (used to pick the mutated repository). Concretely:

- `WebhooksController#repository_owner` reads `params.dig('repository','owner','login')` (falling back to `organization.login`) and passes it to `Shipit.github(organization: repository_owner)` to fetch that org's `GitHubApp`, then calls `verify_webhook_signature` [1](#0-0) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` is configured for that org [4](#0-3) . Per `docs/setup.md`, `webhook_secret` is optional/nilable per-org [5](#0-4) .
- Once `verify_signature` passes, `Shipit::Webhooks.for_event('pull_request')` dispatches to handlers such as `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler` [6](#0-5) , each of which resolves the repository purely from `params.repository.full_name`, independent of `owner.login`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [3](#0-2) .
- `ClosedHandler#process` then calls `review_stack.archive!`, which through `ReviewStackAdapter#archive!` calls `stack.remove_from_provisioning_queue`, `stack.deprovision`, and `stack.archive!(user, ...)` on the resolved (victim) stack [7](#0-6) .

Exploit flow: the attacker (who owns/controls a no-secret-configured org, e.g. one they registered as a Shipit-tracked org with no `webhook_secret`) crafts a raw `pull_request` `closed` event where `repository.owner.login` = their own no-secret org, but `repository.full_name` = `"victim-org/victim-repo"`. Since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` for *any* signature (or none). `verify_signature` passes, the event is dispatched, and `ClosedHandler` resolves the victim's repository via `full_name` and archives the victim's active review stack — a state change on a repository/org whose secret never verified this payload.

None of the existing guards catch this: `drop_unhandled_event` only checks the event name is registered [8](#0-7) ; `verify_signature` only checks the org named by `owner.login`, never cross-checking against `full_name`'s owner; the `ExplicitParameters` schema on each handler only requires `repository.full_name` to be a `String`, with no relation validated back to `owner.login` [9](#0-8) ; there is no session/user/API-client authorization involved at all in this unauthenticated endpoint.

### Impact Explanation
An unauthenticated, unprivileged attacker can archive (deprovision) an active review stack belonging to any repository/org tracked by the Shipit instance, as long as any org in the Shipit config has no `webhook_secret` set — a documented, supported configuration [10](#0-9) . This is a cross-tenant state mutation: a payload nominally "signed" (or unsigned) for org A causes writes to org B's/victim's `ReviewStack`/`Stack` records (`deprovision`, `archive!`) [7](#0-6) . This is repeatable against any repository/PR whose `full_name` and current environment/branch the attacker can guess or observe, matching the "Critical: payload for one repository mutating another's stack" category.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured with the multi-org github config schema (`github: {org: {...}}`) with at least one org lacking a `webhook_secret` — a supported and documented setup, not a misconfiguration outside the engine's control model [11](#0-10) . The attacker needs no credentials, no Shipit session, and no knowledge of any secret — only the ability to send an HTTP POST to `/webhooks` with a crafted JSON body and the correct `X-Github-Event: pull_request` header. This is fully repeatable and requires no interaction with the real GitHub API.

### Recommendation
In `WebhooksController#verify_signature`/`repository_owner`, derive the org used for signature verification from `repository.full_name`'s owner segment (or require it to match `repository.owner.login` exactly, rejecting the request on mismatch) before dispatching to handlers, so the org that authenticates the payload is provably the org whose data the handler mutates.

### Proof of Concept
Minitest plan (no live GitHub):
1. Configure two orgs in `Shipit.stubs(:secrets)`: `attacker_org` with `webhook_secret: nil`, `victim_org` with `webhook_secret: "s3cr3t"`.
2. Create `victim_org/victim_repo` `Shipit::Repository` with an active, non-archived `ReviewStack` for PR #1 (`environment: "pr1"`, `branch: "feature"`).
3. Build a `pull_request` `closed` payload: `repository.owner.login = "attacker_org"`, `repository.full_name = "victim_org/victim_repo"`, `pull_request.number = 1`, matching head ref.
4. POST to `/webhooks` with header `X-Github-Event: pull_request` and an arbitrary/garbage `X-Hub-Signature` (since `attacker_org` has no secret, `verify_webhook_signature` returns `true` regardless).
5. Assert response is `200 OK` (not `422`).
6. Assert equality-before: `victim_review_stack.archived? == false` before the request.
7. Assert equality-after: `victim_review_stack.reload.archived? == true` after the request — demonstrating the org that "verified" the webhook (`attacker_org`, no secret) differs from the org whose stack was mutated (`victim_org`, has secret), proving the invariant "a forged webhook cannot cause state change attributed to a repository/org whose secret did not verify it" is violated.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
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

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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
