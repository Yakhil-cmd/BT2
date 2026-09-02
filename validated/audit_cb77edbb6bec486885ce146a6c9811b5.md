### Title
Webhook organization used for signature verification differs from repository acted upon by event handlers - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify a webhook against using `repository_owner`, which is read from the attacker-influenceable payload field `params.dig('repository', 'owner', 'login')`. Once the signature check passes, the actual event handlers (e.g. `PushHandler`) resolve the `Stack`/`Repository` to act on using a **different** payload field, `payload.dig('repository', 'full_name')`. These two fields are never checked for consistency, so a webhook that is validly signed for one GitHub organization can be crafted to act on a repository belonging to a completely different organization.

### Finding Description [1](#0-0) 
`verify_signature` computes:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 
and uses it to pick `Shipit.github(organization: repository_owner)` and verify `X-Hub-Signature` against that organization's configured `webhook_secret`. [3](#0-2) 

After the signature is accepted, `create` dispatches the raw, attacker-controlled JSON body to the registered handler for the event, e.g. `PushHandler`, without re-checking which organization actually owns the target repository: [4](#0-3) 

`Handler#stacks` (the base class used by `PushHandler` and others) resolves the repository/stack to operate on from a **separate** field, `payload.dig('repository', 'full_name')`: [5](#0-4) 

`PushHandler#process` then triggers a GitHub sync for every non-archived stack on the resolved repository matching the pushed branch, using an attacker-supplied `after` SHA: [6](#0-5) 

This is exactly the "organization that authenticated versus the repository that is written" binding break: the org whose secret validated the HMAC (`repository.owner.login`) is not cryptographically bound to the org/repo whose state is subsequently mutated (`repository.full_name`).

### Impact Explanation
An attacker who legitimately controls a GitHub organization/app installation registered in Shipit (i.e., possesses that org's `webhook_secret`, which is only a delivery secret — not a Shipit account or `ApiClient` token) can:
1. Sign a webhook payload with their own organization's secret so `verify_signature` passes (`repository.owner.login` = attacker's org).
2. Set `repository.full_name` in the same payload to `victim-org/victim-repo`, a repository actually tracked as a Shipit `Stack` under a different, victim organization/installation.
3. Have `PushHandler` (or any other handler that resolves via `Handler#stacks`) invoke `stack.sync_github(expected_head_sha: params.after)` against the victim's stack, forcing Shipit's view of the victim repository's HEAD to an attacker-chosen SHA.

Because continuous deployment and merge-queue behavior in Shipit react to synced HEAD state and commit status, this crosses a repository-ownership trust boundary the app is supposed to enforce via per-organization webhook secrets, and can affect deploy/merge state for a repository the attacker does not control — matching the "unauthorized deploy" style impact class.

### Likelihood Explanation
Requires the attacker to control at least one GitHub organization/app installation configured in this Shipit instance's `secrets.yml` (with its own `webhook_secret`) — a normal, unprivileged registration precondition, not a compromise of Shipit itself or of the victim org. No Shipit session, `ApiClient` token, or GitHub write access to the victim repository is needed. The mismatch is a straightforward, deterministic logic flaw in the two independent field lookups, not a probabilistic condition.

### Recommendation
Bind the fields used for authentication and for action: after computing `repository_owner` in `verify_signature`, the controller (or `Handler#stacks`) should confirm that the resolved `Repository`'s owner/organization matches `repository_owner` used for signature verification before acting on it — e.g., verify `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.owner == repository_owner` (or equivalent) prior to invoking handlers, and reject/ignore the event otherwise.

### Proof of Concept
1. Attacker registers `attacker-org` as a Shipit GitHub App installation with `webhook_secret = S`.
2. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)` for a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker_chosen_sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. POST this to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner = "attacker-org"`, validates the signature against `attacker-org`'s secret — passes.
5. `PushHandler` resolves `stacks` via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`, and calls `sync_github(expected_head_sha: "<attacker_chosen_sha>")` on that victim stack, even though the attacker never proved control over `victim-org`.

Note: I was unable to fully retrieve the contents of `app/models/shipit/webhooks/handlers/membership_handler.rb` before the tool budget ended (only grep matches for `organization`/`team` were confirmed, not full logic), so I cannot confirm whether the same organization/data mismatch additionally allows forged `membership` webhooks to manipulate `Shipit.github_teams`-based authorization. That would be a natural follow-up to verify, as it could raise the impact from stack-state manipulation to authorization escalation.

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
