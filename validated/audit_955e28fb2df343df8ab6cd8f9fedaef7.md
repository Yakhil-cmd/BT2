### Title
Webhook signature verification is scoped to the payload's `repository.owner.login`, not to the stack/organization actually written by the handler - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the *unauthenticated* request body, and then dispatches the *same* untrusted body to handlers that look up stacks by `repository.full_name`/branch. The binding the code should enforce is: "the organization whose secret verified this signature" == "the organization/repository whose stack the handlers mutate." Nothing enforces that equality.

### Finding Description
`verify_signature` resolves the signing organization from attacker-controlled JSON before any cryptographic check has occurred: [1](#0-0) . It then fetches that organization's `GitHubApp` and calls `verify_webhook_signature`: [2](#0-1) .

`GitHubApp#verify_webhook_signature` trivially returns `true` whenever that organization has no `webhook_secret` configured: [3](#0-2) . Multi-org Shipit deployments are explicitly supported (`config/secrets.development.shopify.yml` shows multiple orgs, each with its own optional `webhook_secret`) [4](#0-3) .

Once `verify_signature` passes, `create` parses the same raw body and hands it to event handlers keyed only by `X-Github-Event`, with no re-check that the "verified" organization matches the repository the handler will act on: [5](#0-4) . Handlers such as `PushHandler` locate stacks purely by branch name across the `stacks` scope derived from `params.repository.full_name` via the base `Handler` resolution, and pull-request handlers resolve repositories independently with `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [6](#0-5)  and `PushHandler#process` [7](#0-6) .

Because the organization used for signature verification (`repository.owner.login`) and the repository/stack actually acted upon (`repository.full_name`) are both taken from the same untrusted JSON body but never checked against each other, an attacker can supply mismatched values: put an organization with no `webhook_secret` (or a leaked/guessable one) in `repository.owner.login` to satisfy `verify_signature`, while setting `repository.full_name` to point at a stack belonging to a *different*, properly-secured organization. The equality the code should enforce and does not is:
`organization whose webhook_secret authenticated the request == organization owning the repository/stack the handler writes to`.

### Impact Explanation
This breaks the trust boundary between "an authenticated GitHub webhook for org X" and "state mutation of stack/repository Y." Concretely, an unprivileged external attacker who merely knows (a) that a target Shipit instance hosts multiple GitHub orgs and (b) that at least one configured org has no `webhook_secret` set (the common/default state per `secrets.development.shopify.yml`, where `webhook_secret:` is commonly left `nil`), can forge unsigned webhook POSTs that pass `verify_signature` and then trigger `GithubSyncJob` (which triggers deploy pipeline synchronization) for stacks belonging to a fully-secured organization, create arbitrary `Team`/`User` records via the `membership` handler, or manipulate `PullRequest`/`check_suite`/`status` records for repos never owned by the attacker-controlled org. This crosses the intended repository/credential boundary and can lead to unauthorized state changes feeding into deploy/rollback triggers, satisfying the "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Likelihood is contingent on the specific multi-org configuration: it requires at least one configured GitHub organization in the Shipit installation with no `webhook_secret` set (or one whose secret has otherwise been obtained), while other configured organizations use secrets. This is a realistic, commonly-seen configuration (the shipped example secrets file leaves `webhook_secret:` blank), and the request itself is trivial to craft (a single unauthenticated

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
