### Title
Webhook signature verification key selected from an unverified payload field that differs from the field used to select the acted-upon repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/organization (and thus the `webhook_secret` used to validate the `X-Hub-Signature` HMAC) from an unauthenticated field of the *incoming, not-yet-verified* payload: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The HMAC is checked against `Shipit.github(organization: repository_owner)`'s configured secret, i.e. whichever GitHub App/org the payload *claims* to be from, as configured in `secrets.yml` (Shipit explicitly supports multiple GitHub Apps keyed by organization, see `test/dummy/config/secrets_double_github_app.yml`).

However, every event handler that actually mutates state resolves the target repository from a *different* JSON field of the same payload — `repository.full_name` — and never cross-checks it against `repository.owner.login`: [3](#0-2) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` uses this `stacks` scope directly to trigger a sync: [4](#0-3) 

and the `pull_request/*` handlers (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`, `LabeledHandler`) independently resolve the repository via `params.repository.full_name` to archive/unarchive/create review stacks: [5](#0-4) [6](#0-5) 

This is the exact analog of the reported bug class: the entity that *authenticates* the request (the organization used to pick the verification secret, from `repository.owner.login`/`organization.login`) is not bound to the entity that is actually *written to* (the repository/stack resolved from `repository.full_name`). The trust binding `signing_org == acted_upon_repo.owner` is never enforced — the two are read from independent, attacker-controlled JSON keys in the same request body.

### Impact Explanation
Any party that legitimately operates one GitHub App/organization onboarded to this Shipit instance (i.e., possesses a valid `webhook_secret` for *their own* org, as configured under a distinct key in `secrets.yml`, e.g. `OrgTwo` in `secrets_double_github_app.yml`) can craft a payload whose HMAC is computed correctly with `OrgTwo`'s secret, set `repository.owner.login` (or `organization.login`) to `OrgTwo` so the signature check passes, but set `repository.full_name` to `OrgOne/victim-repo` — a stack belonging to a completely different, unrelated organization tracked in the same Shipit instance. `verify_signature` will accept the request (correct HMAC for `OrgTwo`), while the handler dispatch operates on the victim's stack via `repository.full_name`.

Concretely this lets a cross-tenant attacker (who does not control `OrgOne` at all) force `PushHandler` to enqueue `GithubSyncJob` for `OrgOne`'s stack with an attacker-chosen `expected_head_sha`, and force the `pull_request` handlers to archive/unarchive/create review stacks belonging to `OrgOne`, purely by forging fields inside a request signed with their own, unrelated app credentials. This is an unauthorized state change on a stack/repository the attacker does not control, satisfying the "cross-repository writes" impact class from an unprivileged, cross-tenant position (no Shipit session, API token, or victim's webhook secret required).

### Likelihood Explanation
Exploitability requires only that the deployment configures more than one GitHub App/organization (a documented, supported configuration — see `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`) and that the attacker legitimately controls one of those onboarded orgs/apps. Any such org member can locally compute a valid signature for their own secret and simply change the `repository.owner.login`/`full_name` combination in the JSON body before sending it to the shared `/github/webhooks` endpoint — no interception, no privileged Shipit account, and no knowledge of the victim org's `webhook_secret` is needed.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select/verify the signing secret matches the owner of the repository the handler is about to act on, e.g. assert `payload.dig('repository','full_name')&.split('/')&.first&.downcase == repository_owner&.downcase` before dispatch, and reject (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` using the same verified `repository_owner` value rather than trusting an independent `full_name` field.

### Proof of Concept
1. Operator of `OrgTwo` (onboarded as a legitimate GitHub App in this Shipit instance per `secrets.yml`) computes `sha1=HMAC(OrgTwo_webhook_secret, body)`.
2. They send:
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<valid for OrgTwo secret>
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": {"login": "OrgTwo"},
    "full_name": "OrgOne/victim-repo"
  }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgTwo"`, verifies the HMAC successfully against `OrgTwo`'s secret [1](#0-0) .
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` from `repository.full_name = "OrgOne/victim-repo"` [3](#0-2)  and enqueues `GithubSyncJob` for that unrelated stack [4](#0-3) , despite the request never being signed by `OrgOne`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
