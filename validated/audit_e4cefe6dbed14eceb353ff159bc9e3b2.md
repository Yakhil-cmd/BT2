## Title
Webhook signature verified against `repository.owner.login`'s GitHub App while the event is applied to the repository named by `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

## Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to use for HMAC verification from `repository.owner.login` (or `organization.login`), but every event handler resolves the repository/stack to act on from a completely different payload field, `repository.full_name`. Nothing ties these two fields together, so the org whose credential authenticated the request is not provably the org whose repository gets written to.

## Finding Description
`verify_signature` computes the signing organization like this: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This means the request is authenticated against whichever GitHub App/organization secret matches `repository.owner.login` in the JSON body — an attacker-controlled field, not something GitHub itself signs into a fixed value that Shipit cross-checks.

Every downstream handler, however, resolves the target repository/stack from a different field, `repository.full_name`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

The same pattern (`params.repository.full_name`) is used to resolve repositories in `PushHandler`, `PullRequest::OpenedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`, `AssignedHandler`, etc. There is no assertion anywhere that the owner segment of `full_name` matches `repository.owner.login` (the field used for signature selection).

In Shipit's supported "Using Multiple Github Applications" configuration, each organization is configured with its own `webhook_secret` (see `docs/setup.md`). This means the binding that should hold is:

`organization authenticated (repository.owner.login) == organization of the repository actually written (repository.full_name)`

Because this equality is never checked, an attacker who has a valid signing secret for organization A (e.g., they administer their own GitHub App/webhook configuration for org A, which is installed as a legitimate but distinct organization in this multi-tenant Shipit instance) can craft a webhook body with:
- `repository.owner.login = "orgA"` (or `organization.login = "orgA"`) so `verify_signature` selects and validates against org A's secret,
- `X-Hub-Signature` computed with org A's actual secret,
- `repository.full_name = "orgB/victim-repo"` — a repository belonging to a different, unrelated organization tracked by the same Shipit instance.

`verify_signature` passes (org A's HMAC matches), but every handler that runs afterwards acts on `orgB/victim-repo`, because `repository_name`/`stacks` resolution never revisits `repository.owner.login`.

## Impact Explanation
This is a cross-organization/cross-repository write reachable purely from a forged webhook body, requiring only a webhook secret for *any* organization configured in the same Shipit instance (not the target organization). Concretely:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on stacks belonging to `orgB/victim-repo`, letting an org-A-authenticated request drive GitHub sync state (attacker-chosen `expected_head_sha`) for a stack it does not own.
- `PullRequest` handlers (`OpenedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`) create, archive/unarchive, or update `ReviewStack`s and `PullRequest` records for `orgB`'s repositories/PRs based on forged `pull_request` payload contents.
- Any handler resolving repository state by `full_name` is affected the same way.

This matches the "cross-repository writes" / organization-authentication-vs-repository-written binding called out explicitly in scope, and the affected code lives entirely in `app/controllers/shipit/webhooks_controller.rb` and `app/models/shipit/webhooks/handlers/**`, both in scope.

## Likelihood Explanation
Requires only: (1) a Shipit deployment configured with more than one GitHub App/organization (documented, supported feature — `docs/setup.md`'s "Using Multiple Github Applications" section), and (2) the attacker controlling a valid webhook secret for any one of those configured organizations (e.g., their own org's GitHub App settings, which they legitimately administer). No repository write access, GITHUB_TOKEN, or Shipit session is needed — only knowledge of one org's webhook secret, which is exactly the credential webhook delivery is supposed to be scoped to. This is a plausible, non-theoretical misuse of the multi-org feature as implemented.

## Recommendation
Bind the field used for authorization/secret-selection to the field used for resolution:
- After `verify_signature` succeeds, re-derive `repository_owner` from the same value used by handlers to resolve the target repository (`repository.full_name`'s owner segment), and reject (422) if they don't match.
- Alternatively, verify the signature using the config that corresponds to the resolved repository's actual configured organization (looked up from `Repository.from_github_repo_name`), not from an unauthenticated payload field, and re-verify signature/organization consistency inside `Handlers::Handler#stacks`/`#repository_name` rather than only in the controller.

## Proof of Concept
1. Shipit instance is configured with two GitHub App entries, `orgA` and `orgB`, each with its own `webhook_secret` (per the multi-org config in `docs/setup.md`).
2. Attacker controls `orgA`'s GitHub App/webhook secret (legitimately, as its admin) and knows `orgB/victim-repo` is tracked in the shared Shipit instance.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
4. `X-Hub-Signature` is computed as `sha1=HMAC(orgA_webhook_secret, raw_body)`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")` and verifies successfully.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker chosen sha>")` on `orgB`'s stack — a write triggered by an org-A-authenticated request against an org-B resource. [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
