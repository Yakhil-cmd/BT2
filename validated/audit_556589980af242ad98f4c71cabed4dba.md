### Title
Cross-organization webhook confused deputy: signature verified against payload-supplied organization, but handlers act on a payload-supplied repository never bound to that organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the `X-Hub-Signature` against using a field taken from the same untrusted JSON body it is validating (`repository.owner.login`), while the event handlers that actually mutate application state key off a *different* field of that same body (`repository.full_name`). Nothing binds these two fields together, so a party who legitimately controls one tenant organization configured in a multi-organization Shipit deployment can forge a fully custom, validly-signed webhook payload that claims to originate from their own org but names a victim organization's repository, causing the victim's stacks to be acted upon.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
`verify_signature` computes: [2](#0-1) 
`repository_owner` is read straight out of the attacker-suppliable request body (`params.dig('repository','owner','login')`) and used to pick which organization's secret in `Shipit.github(organization: repository_owner)` (`lib/shipit.rb`, `github`/`github_app_config`) validates the HMAC over the *entire raw body* (`lib/shipit/github_app.rb#verify_webhook_signature`).

Once the signature check passes, `create` re-parses the same body and dispatches to handlers: [3](#0-2) 
Handlers resolve the target stacks using a completely different field of the same body, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

`PushHandler` uses this to enqueue a sync against arbitrary attacker-chosen SHAs for whatever stacks match `repository.full_name`: [5](#0-4) 

`StatusHandler` is worse: it does not even consult `repository`/`stacks` — it looks up *any* commit in the entire database by SHA and writes a CI status onto it, regardless of which repository/org it belongs to: [6](#0-5) 

The binding that is broken is: **organization that authenticated (`repository.owner.login` used to select the verifying `webhook_secret`) ≠ repository that is written (`repository.full_name` used by handlers, or no repository check at all for `StatusHandler`)**.

Before the attack: for a legitimate GitHub webhook, `repository.owner.login` and `repository.full_name`'s owner segment are always consistent, because GitHub itself constructs and signs the payload from real event data.

After the attack: an attacker who administers `attacker-org` (one tenant configured with its own `webhook_secret` in `secrets.github[attacker-org]`) can craft an arbitrary JSON body, e.g.:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
sign it with their own real `webhook_secret`, and send it to the shared `/webhooks` endpoint with `X-Github-Event: push`. `verify_signature` succeeds because it only validates against `attacker-org`'s secret. `PushHandler` then finds the `victim-org/victim-repo` stack via `Repository.from_github_repo_name` and enqueues `GithubSyncJob` for it with an attacker-controlled `expected_head_sha`.

### Impact Explanation
This crosses a repository/organization authentication boundary: a tenant that only owns and administers its own GitHub organization inside a shared, multi-organization Shipit instance can inject events into any other tenant's repository/stack, without any credential belonging to the victim. Concretely:
- `PushHandler` can trigger `GithubSyncJob` for a victim stack with an attacker-chosen `expected_head_sha`, which fetches and appends commits from GitHub for that stack — potentially causing continuous-deployment-enabled stacks to sync/deploy commits the attacker chooses to reference.
- `StatusHandler` can forge a `success` CI status on *any* commit row in the database regardless of owning repository, which can satisfy `required_statuses`/CI gating logic used to decide `deployable?`, letting an attacker manufacture a fraudulent "green" CI signal for a victim's commit and help unlock deploys that should have been blocked.
- Other handlers (`check_suite`, pull-request handlers) are similarly reachable via a forged-but-validly-signed body naming an arbitrary `repository.full_name`.

This matches the "escalation into unauthorized/forced deploy" and "unauthenticated read/write of stack state" impact classes described as in-scope, without requiring the victim's GitHub App private key, `webhook_secret`, or a Shipit session/API token — only possession of the attacker's own legitimately-issued secret for a co-tenant organization.

### Likelihood Explanation
This requires a multi-organization Shipit deployment (`secrets.github` keyed by organization, as supported by `Shipit.github`/`github_app_config`) hosting more than one tenant behind a single `/webhooks` endpoint — a configuration explicitly supported by the engine. Any tenant admin who can configure/inspect their own organization's GitHub App webhook secret can mount this attack against any other tracked repository, with no interaction from the victim required.

### Recommendation
Bind the verified organization to the repository being acted upon:
- After (or as part of) `verify_signature`, ensure the resolved `repository.full_name`'s owner matches `repository_owner` before dispatching to handlers, or resolve the target `Repository`/`Stack` first and verify the signature using the secret associated with that repository's actual configured organization (not an attacker-suppliable field of the payload).
- In `Shipit::Webhooks::Handlers::Handler` and `StatusHandler` in particular, scope lookups (e.g., `Commit.where(sha:)`) to the repository resolved from a trusted binding rather than trusting `repository.full_name` from the payload alone.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `github.webhook_secret` (multi-org config per `lib/shipit.rb#github_app_config`), both tracking stacks/repos in the same Shipit instance.
2. As the administrator of `attacker-org`'s GitHub App, obtain `attacker-org`'s `webhook_secret` (a credential the attacker legitimately possesses for their own org).
3. Build a raw JSON push payload:
```json
{"ref":"refs/heads/master","after":"<attacker-chosen-sha>","repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"}}
```
4. Compute `X-Hub-Signature: sha1=<hmac-sha1(attacker-org-webhook-secret, raw_body)>`.
5. `POST /webhooks` with headers `X-Github-Event: push` and the computed signature.
6. `WebhooksController#verify_signature` passes (it only checks against `attacker-org`'s secret). `PushHandler` resolves `victim-org/victim-repo`'s stacks via `repository.full_name` and enqueues `GithubSyncJob` with the attacker-chosen `expected_head_sha` against the victim's stack — demonstrating cross-tenant write access using only the attacker's own webhook credentials.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
