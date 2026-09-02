### Title
Cross-organization review-stack creation via mismatched `repository.owner.login` vs `repository.full_name` in webhook payload - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` derives the organization used for signature verification from `params.dig('repository','owner','login')`, while `PullRequestOpenedHandler#repository` independently resolves the target `Shipit::Repository` from `params.repository.full_name` by splitting it into owner/name. These two fields are never checked for consistency, and `GitHubApp#verify_webhook_signature` trivially returns `true` whenever the resolved organization has no `webhook_secret` configured. An attacker who controls (or names) an organization with no configured webhook secret can submit a payload whose `repository.owner.login` is that unsecured organization while `repository.full_name` names an unrelated victim repository, causing a review stack to be created and attached to the victim's `Repository`.

### Finding Description
The claimed binding is: `organization used to verify the webhook signature` (`params.dig('repository','owner','login')` in `app/controllers/shipit/webhooks_controller.rb:59-62`) `== organization owning the Repository a review stack gets attached to` (derived from `params.repository.full_name` in `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54` and `Shipit::Repository.from_github_repo_name`, `app/models/shipit/repository.rb:53-56`).

Tracing the code:
- `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` and then `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) . `repository_owner` reads only `params.dig('repository','owner','login')` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization: `return true unless webhook_secret` [3](#0-2) . Multi-org configuration is supported and documented, and any org can independently have `webhook_secret: nil` [4](#0-3) [5](#0-4) .
- `PullRequestOpenedHandler#repository` resolves the target repository from an entirely different payload field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name`, which just splits the string on `/` and does `find_by(owner:, name:)` [6](#0-5) [7](#0-6) .
- Nothing in the request pipeline checks that `params.repository.owner.login` matches the owner segment of `params.repository.full_name`. Both are attacker-supplied JSON fields from the same POST body (`JSON.parse(request.raw_post)` in `WebhooksController#create`), with no cross-field validation, and the `ExplicitParameters` schema for the opened handler only requires `repository.full_name` to be a `String` [8](#0-7) .

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request` and a JSON body where `repository.owner.login = "attacker-org"` (an org with no `webhook_secret` configured, e.g. attacker's own installed app or any org left unsecured) but `repository.full_name = "victim-org/victim-repo"`. `verify_signature` looks up `Shipit.github(organization: "attacker-org")`, finds no secret, and returns `true` regardless of the (even garbage) `X-Hub-Signature` header. Processing then proceeds to `OpenedHandler#process`, which resolves `repository` from `full_name` = victim's actual `Shipit::Repository` row, and calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [9](#0-8) . `ReviewStackAdapter#create!` builds a `ReviewStack` (a `Stack` subtype) using fully attacker-controlled `branch: params.pull_request.head.ref`, `environment: "pr#{params.number}"`, and persists a `PullRequest` record from `params.pull_request`, all scoped to the victim's repository [10](#0-9) . This is only gated by `repository.review_stacks_enabled` / provisioning-behavior settings, which are attributes of the victim repository, not an authentication control [11](#0-10) .

Existing guards fail because: `drop_unhandled_event` only checks the event type; `ExplicitParameters` only enforces field presence/type, not cross-field owner consistency; `Repository` model validations only constrain the format/length of `owner`/`name` on the DB record, not that a webhook's claimed signing org matches the target repo's owner; and `verify_signature`'s trust decision is keyed off a field (`repository.owner.login`) that is disjoint from the field actually used to select the mutated record (`repository.full_name`).

### Impact Explanation
An unauthenticated attacker can create a `Shipit::ReviewStack` and an associated `Shipit::PullRequest` row under any victim repository configured with `review_stacks_enabled` and a permissive provisioning behavior (`allow_all`, or label-based behaviors the attacker can also satisfy since `labels` are attacker-controlled payload fields), without ever possessing the victim organization's webhook secret, GitHub App keys, or any Shipit credential. Because `ReviewStackProvisioningQueue.add(stack)` is invoked on creation, this can trigger provisioning/deploy-adjacent workflows for the victim's stack from attacker-chosen branch/ref data. This is repeatable against any repository/organization as long as some organization known to the attacker (their own, or any other misconfigured org) has no `webhook_secret` set — a cross-repository/cross-tenant mutation matching the "Critical: payload for one repository mutating another's stack" category.

### Likelihood Explanation
Preconditions: (1) at least one GitHub organization configured in Shipit's `github` secrets section has no `webhook_secret` set (the shipped example configs and docs default `webhook_secret` to blank/nil [12](#0-11) , and multi-org deployments are an explicitly documented and supported pattern), and (2) the victim repository has review-stack provisioning enabled. No authentication, session, API token, or knowledge of any secret is required — the attacker only needs to send one crafted HTTP POST. This is low-cost and fully repeatable per victim repository/PR number.

### Recommendation
Bind the signature-verification organization to the same field used to resolve the target repository (e.g., derive both from `repository.full_name`'s owner segment, or explicitly validate `repository.owner.login == full_name.split('/').first` before further processing) so that a webhook can only be trusted for — and can only mutate — repositories under the organization whose secret actually verified it. Additionally, consider rejecting webhooks entirely when the resolved organization has no `webhook_secret` configured in production, rather than treating a missing secret as "verification passed."

### Proof of Concept
Minitest plan (no live GitHub calls; use existing fixtures under `test/fixtures/payloads` such as `pull_request_opened.json`, stubbing/using `test/dummy/config/secrets_double_github_app.yml`-style config with `OrgOne` having no `webhook_secret`):

1. Set up `Shipit.secrets.github` with two orgs: `OrgOne` (attacker-controlled, `webhook_secret: nil`) and the victim repository fixture's real owner, e.g. `shipit_repositories(:shipit)` with `owner: "shopify"`.
2. Build a payload from `payload(:pull_request_opened)`, then overwrite `payload["repository"]["owner"]["login"] = "OrgOne"` while leaving `payload["repository"]["full_name"] = "shopify/shipit-engine"` (the victim repo fixture's real full name), and set `payload["pull_request"]["head"]["ref"]` to an attacker-chosen branch name.
3. POST to `/webhooks` with `X-Github-Event: pull_request` and any bogus `X-Hub-Signature` value.
4. Assert:
   - Left side of the binding: `repository_owner` resolved by the controller equals `"OrgOne"`.
   - Right side of the binding: the `Shipit::Repository` mutated equals `shipit_repositories(:shipit)` (owner `"shopify"`).
   - `assert_response :ok` (i.e., `verify_signature` passed despite the bogus signature, because `OrgOne` has no secret).
   - `assert_difference -> { Shipit::Stack.count }, 1` and `assert_difference -> { Shipit::PullRequest.count }, 1`.
   - `shipit_repositories(:shipit).review_stacks.last.branch` equals the attacker-supplied `head.ref`, proving the stack was created and attached to the victim repository from a payload verified against a different ("OrgOne") organization's (non-existent) secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** config/secrets.development.example.yml (L1-17)
```yaml
host: 'localhost:3000'
redis_url: 'redis://127.0.0.1:6379/0'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app
# Can be obtained there: https://github.com/settings/apps
# Set the "Authorization callback URL" as `<host>/github/auth/github/callback`

github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional

```
