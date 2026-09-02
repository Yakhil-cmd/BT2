### Title
Webhook signature verified against `repository.owner.login` while handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound GitHub webhook using the `repository.owner.login` field taken from the *unverified* JSON body, then, once "verified", the same raw payload is dispatched to handlers that resolve the target `Stack`/`Repository` using an entirely different field, `repository.full_name`. Because a Shipit instance can be configured for multiple GitHub organizations (each with its own webhook secret, resolved via `Shipit.github(organization: ...)`), an attacker who controls one onboarded organization's webhook secret can craft a payload whose `owner.login` matches their own org (so it passes signature verification with a secret they legitimately possess) while `repository.full_name` points at a victim's repository/stack, causing the handler to act on that unrelated repository.

### Finding Description
The controller resolves the verifying GitHub App/secret purely from attacker-controlled JSON before any cryptographic check occurs: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end
```

`repository_owner` is derived from the same untrusted body: [2](#0-1) 

Once verification passes, the full parsed body is handed to the event handlers unmodified: [3](#0-2) 

The handlers, however, do not re-check that the repository they act on belongs to the organization whose secret validated the request. They resolve the target repository from a *different* field of the same payload: [4](#0-3) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler#process`, for example, uses this `stacks` lookup driven by `repository.full_name` to trigger `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack: [5](#0-4) 

Because `Shipit.github(organization:)` supports per-organization configuration (multiple installed GitHub Apps/secrets, with an explicit `GithubOrganizationUnknown` error path for unrecognized ones), a Shipit deployment onboarding more than one GitHub organization creates exactly the binding break described by the equality:

`repository.owner.login` (organization whose secret authenticates the request) ≠ `repository.full_name` (repository the handler actually writes to/acts on).

An attacker who is a legitimate administrator of *their own* onboarded organization (and therefore knows/controls their own org's webhook secret) can send a signed webhook request where `owner.login` is their own org (passing `verify_signature`) but `repository.full_name` is set to `victim-org/victim-repo`. The signature check never inspects `full_name`, so the forged payload is accepted and dispatched to handlers that operate on the victim repository's stacks.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out in scope. Depending on which event/handler is exercised, the attacker can force `PushHandler` to invoke `stack.sync_github` against a victim stack, or drive other handlers (e.g. status/check_suite/pull_request family) to mutate state (commits, statuses, merge/PR bookkeeping) belonging to a repository the attacker has no legitimate access to — effectively a cross-repository/cross-organization write triggered purely by control of an unrelated organization's webhook secret.

### Likelihood Explanation
Requires the attacker to control (as an unprivileged, legitimate admin) at least one GitHub organization/app that is separately onboarded onto the same Shipit instance — a realistic scenario for any multi-tenant Shipit deployment serving more than one organization. No access to the victim organization, its secret, or its repository is needed.

### Recommendation
After signature verification succeeds, re-derive/re-validate that `repository.full_name`'s owner matches the `repository_owner`/organization whose secret validated the request (or, simpler, only ever key off one canonical, verified field for both secret-selection and repository resolution) before dispatching to handlers.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, which is onboarded to the shared Shipit instance with its own webhook secret.
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s own webhook secret over the raw body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and the signature validates successfully.
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stacks — none of which belong to `attacker-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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
