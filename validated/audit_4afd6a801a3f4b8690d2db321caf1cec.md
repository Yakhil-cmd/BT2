### Title
Cross-repository commit status forgery via unscoped `StatusHandler` webhook processing - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App signing secret to validate an incoming webhook based solely on `repository_owner` (`repository.owner.login` or `organization.login` from the payload), but the handler that actually acts on the payload — `StatusHandler` — never re-checks that the commit it mutates belongs to that same, verified repository/organization. This is the same class of bug as the DNS resolver report: the field verified (`repository.owner.login`, used to pick the HMAC secret) is not the field the mutation is bound to (`sha`, used to look up and update `Commit` records globally, across all stacks/repositories).

### Finding Description
`WebhooksController#verify_signature` looks up the GitHub App/secret to verify against using only the organization derived from the payload: [1](#0-0) [2](#0-1) 

Once the signature check passes for *some* configured organization, `WebhooksController#create` dispatches the payload to every registered handler for the event type: [3](#0-2) 

For `status` events, the handler is `StatusHandler`, which resolves the target purely by SHA, with **no scoping to the repository/organization that was verified**: [4](#0-3) 

Compare this to other handlers such as `PushHandler`, which correctly scope to `stacks` derived from `Repository.from_github_repo_name(repository_name)` (i.e., `payload.dig('repository', 'full_name')`): [5](#0-4) [6](#0-5) 

`StatusHandler` inherits from the same base `Handler` (which exposes a `stacks` helper scoped by `repository_name`) but never uses it — `Commit.where(sha: params.sha)` runs against the entire `commits` table, unscoped by repository: [7](#0-6) 

**The trust binding that is broken:** "organization authenticated" (the org whose `webhook_secret` produced a valid `X-Hub-Signature`) must equal "repository whose data is written." For `status` events, the engine authenticates only that *some* onboarded organization signed the payload, then blindly writes a `Status` record for any commit SHA named in the payload body — a field never covered by that per-organization signature binding. An attacker who administers **any** GitHub organization onboarded into this Shipit instance (able to configure a webhook and thus produce validly-signed `status` payloads for their own org) can supply an arbitrary `sha` value belonging to a commit tracked under a **different** organization's stack, and Shipit will create/update a `Status` for it.

### Impact Explanation
Commit statuses feed directly into deploy gating: `Commit#deployable?`/CI requirement checks in `shipit.yml`'s `ci.require` consult exactly the `Status` records `StatusHandler` writes. By forging a `success` state status with a `context` matching a required CI check on a targeted stack's pending commit, a low-privilege actor who controls an unrelated, already-onboarded GitHub organization can make an otherwise CI-blocked commit appear deployable in a repository they do not own, enabling an unauthorized/unreviewed deploy of that commit. This satisfies the "unauthorized deploy" / "cross-repository writes" impact bar, since a webhook signed for organization A results in state changes (Status rows tied to Commits) for a repository/stack that lives in organization B.

### Likelihood Explanation
Exploitation requires only: (1) the attacker administers or controls any GitHub organization already configured in Shipit's `github:` config (a routine, low-privilege position relative to the target repository — they need zero access to the target org/repo), and (2) knowledge of a target commit SHA, which is public information for any repository visible on GitHub (and for private repos, may be knowable through other means such as PR/commit URLs shared internally). No access to the target repository, no Shipit session, and no possession of the target org's `webhook_secret` is required — only the attacker's own org's webhook secret, which they legitimately hold as an org admin. This is a realistic, low-effort attack path.

### Recommendation
In `StatusHandler#process` (and any other handler that does not already scope through `stacks`/`Repository.from_github_repo_name`), restrict the `Commit` lookup to commits belonging to stacks under the repository identified by the verified payload (i.e., use the `stacks` helper from `Handler` to scope `Commit.where(sha: params.sha, stack: stacks)` or equivalent), so that the organization bound to the verified signature is the same organization whose data can be mutated. More generally, `WebhooksController#verify_signature` should ensure the resolved `repository_owner` used for signature verification matches the repository the specific handler is about to write to, rather than trusting any one configured organization's signature to authorize writes referencing arbitrary payload fields.

### Proof of Concept
1. Shipit is configured with two GitHub organizations, `org-attacker` and `org-victim`, each with distinct `webhook_secret`s (multi-org config as shown in `config/secrets.development.example.yml`).
2. Attacker is an admin of `org-attacker` (a real, low-privilege position — no access to `org-victim`) and configures a repository webhook pointed at Shipit's `/webhooks` endpoint, obtaining/knowing `org-attacker`'s `webhook_secret`.
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<commit sha of a pending, CI-gated commit in org-victim/some-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/whatever" }
}
```
4. Attacker computes `X-Hub-Signature` using `org-attacker`'s `webhook_secret` (which they legitimately possess) and POSTs to `/webhooks` with header `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-attacker"`, fetches `Shipit.github(organization: "org-attacker")`, and the signature verifies successfully.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — unscoped by repository — finds the commit belonging to `org-victim/some-repo`, and calls `commit.create_status_from_github!(params)`, creating a forged `success` status on a commit the attacker has no access to, potentially satisfying `ci.require` and unlocking an unauthorized deploy in `org-victim`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L26-38)
```ruby
        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
