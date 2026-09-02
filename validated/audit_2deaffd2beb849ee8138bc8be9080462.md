### Title
Webhook signature verification org selection is decoupled from the repository the payload actually mutates, enabling cross-organization writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/secret to validate an inbound webhook against using an attacker-controlled field of the *same* JSON body it is about to authenticate (`repository.owner.login`, falling back to `organization.login`), while the event handlers that actually mutate state pick the target `Repository`/`Stack` from a *different* field of that same body (`repository.full_name`). Nothing ties these two lookups together, so in a multi-organization Shipit deployment, a valid signature for Organization A's webhook secret authorizes a payload whose `repository.full_name` names a repository belonging to Organization B.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App config to check the signature with like this: [1](#0-0) [2](#0-1) [3](#0-2) 

`repository_owner` is read straight out of the JSON body being verified (`params.dig('repository', 'owner', 'login')`), and it is used only to look up which org's `webhook_secret` to HMAC-check against via `Shipit.github(organization: repository_owner)`: [4](#0-3) 

Once the signature is accepted, the full `params` hash (unscoped, unfiltered) is dispatched to every registered handler for the event: [5](#0-4) 

Handlers determine which `Repository`/`Stack` to act on independently, using `repository.full_name` from the payload — not `repository.owner.login` and not the organization that validated the signature: [6](#0-5) [7](#0-6) 

For example, the push handler syncs whatever stack matches the branch of the repository found via `full_name`: [8](#0-7) 

Because HMAC-SHA1 is computed over the entire raw request body (`request.raw_post`), an attacker cannot alter any field without knowing the signing secret — but the secret used for signing is chosen by `repository.owner.login`, an ordinary field inside the same body, and the engine explicitly supports one Shipit instance servicing multiple independent GitHub organizations, each with its own `webhook_secret` (see `docs/setup.md` "Using Multiple GitHub Applications" and `test/dummy/config/secrets_double_github_app.yml`): [9](#0-8) 

The security-relevant equality that should hold is:
`organization whose webhook_secret validated this request == owner of the repository the payload will act on`

Nothing in `verify_signature` or in `Handler#repository_name` enforces this. Any party who is able to produce a validly-signed body for Organization A (e.g., they administer/are trusted within Org A's GitHub App installation and thus can craft or replay a signed delivery) can set `repository.full_name` to any repository belonging to Organization B configured in the same Shipit instance, and every handler for that event (`push`, `pull_request`, `status`, `check_suite`) will act on Org B's stacks — with no cross-check that Org B ever authorized or even knows about this request.

### Impact Explanation
This breaks the tenant isolation between organizations hosted on a shared multi-org Shipit instance: a request validly signed for Org A can trigger `GithubSyncJob`, `RefreshCheckRunsJob`, commit status writes, or pull-request/review-stack provisioning/archival actions against Org B's stack, i.e. unauthorized cross-repository/cross-organization writes and deploy-pipeline interference performed with no authorization from Org B. This matches the Critical impact bucket "cross-repository writes."

### Likelihood Explanation
Exploitation requires the attacker to be able to produce (or replay) a webhook body validly signed with one configured organization's `webhook_secret` — a capability that is realistic for any legitimate participant of one tenant on a shared, multi-org Shipit deployment (the documented "Using Multiple GitHub Applications" configuration), since GitHub itself will happily sign whatever `repository.full_name` an org's own repositories contain, and Shipit performs no server-side comparison between the two fields. Single-org deployments are unaffected because there is only one possible target. Likelihood is moderate/context-dependent on multi-org usage, but the code path itself contains no compensating control.

### Recommendation
In `WebhooksController#verify_signature`, after determining the organization used to validate the signature, require that every repository referenced inside the verified payload (`repository.full_name`, and any repositories embedded in nested objects such as `pull_request.head.repo`) belongs to that same organization before dispatching to handlers — reject (422) the request otherwise. Alternatively, scope handler-level repository/stack lookups (`Handler#repository_name`, `Repository.from_github_repo_name`) to only the organization that authenticated the request, rather than resolving repositories globally by name.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (per `docs/setup.md`'s multi-org config), each having at least one Stack (`OrgA/app-a`, `OrgB/app-b`).
2. As an entity capable of producing an HMAC-SHA1-signed body using `OrgA`'s `webhook_secret` (e.g., an actor with legitimate access to trigger/replay OrgA GitHub events), craft a `push` event payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/app-b" }
   }
   ```
3. Sign the raw body with `OrgA`'s `webhook_secret` and POST it to `/webhooks` with header `X-Github-Event: push` and the resulting `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully because it was computed with OrgA's real secret.
5. `PushHandler#process` resolves the target via `Repository.from_github_repo_name("OrgB/app-b")` and calls `stack.sync_github(expected_head_sha: ...)` on OrgB's stack — an org that never authorized or signed this request — demonstrating unauthorized cross-organization state mutation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
