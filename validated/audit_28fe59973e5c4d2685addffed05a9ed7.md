### Title
Webhook signature verification keyed on wrong GitHub organization allows cross-repository event forgery when multiple GitHub Apps are configured - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to verify an inbound webhook's HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the **unauthenticated** JSON body, then dispatches the fully-parsed payload to handlers that identify the target `Repository`/`Stack` using a *different* field, `repository.full_name`. Nothing ties the two together, so in a multi-organization deployment (documented and supported via `Shipit.github_organizations`/`github_app_config`) an attacker who legitimately controls the webhook secret for one configured GitHub organization can forge a payload whose `repository.owner.login` names their own org (so it authenticates with their own secret) while `repository.full_name` names a completely different, victim repository/stack tracked by Shipit under another organization's app.

### Finding Description
Signature verification: [1](#0-0) 
selects the app/secret via: [2](#0-1) 

The organization used here is derived purely from attacker-controlled JSON fields (`repository.owner.login` / `organization.login`), before any signature has been validated. `Shipit.github(organization:)` looks up the app config for that org and validates the signature only against that org's `webhook_secret`: [3](#0-2) 

Once verification passes, the entire raw payload (unmodified) is dispatched to all registered handlers for the event: [4](#0-3) 

Every handler resolves the target `Repository`/`Stack` using a **different** field, `repository.full_name`, via `Handler#stacks`/`#repository_name`: [5](#0-4) 
and concretely in, e.g., `PushHandler#process`: [6](#0-5) 
and the various `PullRequest` handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.), which look up the repository by `params.repository.full_name` and then archive/unarchive stacks or create/close review stacks: [7](#0-6) 

Because Shipit explicitly supports multiple independently-configured GitHub Apps/organizations, each with its own `webhook_secret` — documented in `docs/setup.md` and exercised by `test/dummy/config/secrets_double_github_app.yml` and `Shipit.github_organizations`/`Shipit.github_app_config` — the field used to pick the verifying secret (`repository.owner.login`/`organization.login`) is never checked for equality against the field used to select the acted-upon repository (`repository.full_name`). This breaks the trust binding: `organization that authenticated == repository that is written`.

### Impact Explanation
An attacker who controls (or can produce a valid HMAC for) one configured GitHub organization's webhook secret in a multi-org Shipit deployment can:
- Forge a `push` event naming their own org for signature purposes but naming a victim's tracked repository (`repository.full_name`) as the target, causing `Stack#sync_github` to be invoked for that victim stack out-of-band and out of sequence with real GitHub state, since `PushHandler` acts on whatever `full_name` is embedded in the JSON.
- Forge `pull_request` events (`opened`, `closed`, `labeled`, etc.) to archive, unarchive, or otherwise mutate `review_stacks`/`Stack` state belonging to a repository/organization that the attacker's own credential should have no authority over.
- Forge `status`/`check_suite` events to write commit statuses or check-run state for a victim repository's commits, which downstream drives auto-deploy/continuous-delivery decisions (`Stack.schedule_continuous_delivery`), potentially causing an unauthorized deploy.

This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope, and the downstream effect (state mutation on a repository/stack the caller has no legitimate claim to, potentially triggering deploys) meets the High/Critical impact bar (unauthorized state mutation feeding into unauthorized deploy decisions).

### Likelihood Explanation
Requires: (a) the Shipit deployment configured with **multiple GitHub organizations** (an explicitly documented, supported configuration), and (b) the attacker possessing a valid webhook secret for **any one** of those configured organizations (e.g., because they administer that GitHub org/app installation, which is not privileged access to Shipit itself, just to one of several configured upstream integrations). Given that, forging the JSON body fields is trivial — no other check ties the verified org to the acted-upon repository anywhere in the webhook pipeline. Likelihood is moderate: it depends on the multi-org configuration being used, but where it is used, exploitation requires no Shipit credentials, sessions, or tokens at all.

### Recommendation
In `WebhooksController#verify_signature` (or in `Webhooks::Handlers::Handler`), after verifying the signature, additionally verify that the organization used to select the verifying `GitHubApp`/secret matches the owner embedded in `repository.full_name` used by the handlers — i.e., enforce `repository_owner == payload.dig('repository', 'full_name').split('/').first` before dispatching to handlers. Alternatively, have handlers resolve the repository/stack using the same `repository_owner` value that was authenticated, rather than trusting a second, independently-attacker-controlled field.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `AttackerOrg` and `VictimOrg`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker, who administers `AttackerOrg`'s GitHub App installation and therefore knows `AttackerOrg`'s `webhook_secret`, crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha-that-exists-in-VictimOrg/repo>",
     "repository": {
       "owner": { "login": "AttackerOrg" },
       "full_name": "VictimOrg/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(AttackerOrg_webhook_secret, body)` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "AttackerOrg"`, fetches `Shipit.github(organization: "AttackerOrg")`, and successfully verifies the signature using the attacker's own known secret.
5. `PushHandler#process` then looks up `Repository.from_github_repo_name("VictimOrg/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` for the victim's stack — an action the attacker has no legitimate authority over, entirely bypassing the intent of per-organization webhook secrets.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
