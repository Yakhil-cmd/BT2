### Title
Webhook signature is verified against `repository.owner.login`, but events are applied to the stack matched by `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` (falling back to `organization.login`), while every event handler resolves the target `Repository`/`Stack` using the independent `repository.full_name` field. Because nothing enforces that these two attacker-supplied JSON fields agree, a party who legitimately knows the `webhook_secret` for *one* organization configured on the Shipit instance can forge a signature that is valid for that organization while pointing the payload at a completely different organization's repository, causing Shipit to write state (commit statuses, syncs, etc.) for stacks it has no authority over.

### Finding Description
The signature check and the data-selection step read two different attacker-controlled JSON keys: [1](#0-0) [2](#0-1) 

`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and uses it to pick the `GitHubApp` instance (and thus its per-organization `webhook_secret`) via `Shipit.github(organization: repository_owner)`, then verifies the raw request body's HMAC against that secret in `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Once the signature is accepted, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire raw JSON payload* to handlers, which independently derive the target repository from a different key, `repository.full_name`, via `Handler#repository_name` / `Handler#stacks`: [4](#0-3) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks up the record purely by string match, with no cross-check against `repository.owner.login`: [5](#0-4) 

Because Shipit supports multiple organizations each with its own `webhook_secret` (as documented in the multi-org config example), an attacker who administers/knows the webhook secret for `org-A` (their own legitimately configured organization, not a privileged Shipit credential) can POST a JSON body to `/webhooks` where `repository.owner.login = "org-A"` (so the HMAC validates against org-A's secret) but `repository.full_name = "org-B/some-repo"` (so the handler acts on org-B's stacks). This breaks the intended binding: *organization that authenticated == repository that is written*.

Concretely, `StatusHandler` will create a `Status` for any existing commit whose `sha` matches, using attacker-controlled `state`/`description`/`target_url`/`context`, for any commit belonging to `org-B`'s stack: [6](#0-5) 

And `PushHandler` will force a resync of any not-archived stack under `org-B` matching the forged branch/SHA: [7](#0-6) 

### Impact Explanation
This is a cross-organization/cross-repository write: an entity that is only trusted for `org-A`'s webhook traffic can inject fabricated CI status events, forced syncs, and other webhook-driven state changes into stacks owned by any *other* organization configured on the same Shipit instance, without ever holding write access to that other repository or any Shipit session/API token. Forged "success" commit statuses can satisfy `Stack` deployability checks used by continuous deployment, which can lead to an unauthorized deploy being triggered off a commit that never actually passed CI in the real target repository — squarely matching the "unauthorized deploy" / "cross-repository writes" Critical impact category.

### Likelihood Explanation
Exploitation requires only knowledge of a single organization's `webhook_secret` that is already configured on the shared Shipit instance (something the operator of `org-A`'s GitHub App legitimately possesses, e.g. any admin who set up the app for their own org) plus the ability to send an arbitrary HTTP POST to the public `/webhooks` endpoint — no Shipit account, session, or API token is needed. This is a realistic scenario for any multi-tenant Shipit deployment serving more than one organization/team, which the engine explicitly supports.

### Recommendation
Bind the signature-verification identity and the data-mutation identity to the same value:
- After signature verification, re-derive `repository_owner` from the same field used by `Handler#repository_name` (`repository.full_name`'s owner segment) and reject the request (422) if it disagrees with `repository.owner.login`/`organization.login`.
- Alternatively, look up the target `Repository`/`Stack` by its configured organization and confirm that organization's `GitHubApp` is the one whose secret validated the signature before dispatching to handlers.
- Consider verifying the signature per-repository (using the resolved `Repository`'s owner) rather than trusting attacker-supplied fields to select the verification key.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with a distinct `webhook_secret` (per `config/secrets.development.example.yml` multi-org format).
2. As someone who legitimately knows `org-a`'s `webhook_secret` (e.g., the admin of `org-a`'s GitHub App), craft a `push` (or `status`) webhook JSON body where:
   - `repository.owner.login = "org-a"` and `organization.login = "org-a"` (used only for signature selection)
   - `repository.full_name = "org-b/target-repo"` (used by the handler to select the stack to mutate)
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a's webhook_secret, raw_body)>`.
4. POST to `/webhooks` with `X-Github-Event: status` (or `push`). `WebhooksController#verify_signature` validates successfully against `org-a`'s secret.
5. `StatusHandler#process` (or `PushHandler#process`) resolves `stacks` via `Repository.from_github_repo_name("org-b/target-repo")` and writes a forged status / triggers a sync for `org-b`'s stack, despite the request only being authenticated for `org-a`.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
