### Title
Cross-organization signature/target binding break in `Shipit::WebhooksController#verify_signature` allows forged pull_request payloads to mutate another organization's `PullRequest` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`verify_signature` selects the HMAC secret using `params.dig('repository','owner','login')`, while every `PullRequest` webhook handler (e.g. `EditedHandler`) resolves the target repository using the separate field `params.dig('repository','full_name')`. Because these two payload fields are never cross-checked against each other, an attacker who controls the raw JSON body can pick a `repository.owner.login` belonging to an organization with no (or a known) `webhook_secret` for verification purposes, while setting `repository.full_name` to point at a victim organization's repository whose `PullRequest` row gets mutated.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces: `params.dig('repository','owner','login') == owner_of(params.dig('repository','full_name'))`. Nothing in the request path checks this.

Path:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository','owner','login')`. [1](#0-0) [2](#0-1) 
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `@webhook_secret` is blank for that organization: `return true unless webhook_secret`. [3](#0-2) 
3. `#create` re-parses `request.raw_post` and dispatches to the matching handler(s) for the event, passing the fully attacker-controlled JSON. [4](#0-3) 
4. `EditedHandler#repository` resolves the repository using an entirely different field, `params.repository.full_name`, with no relation to `repository_owner` used in step 1. [5](#0-4) 
5. `EditedHandler#pull_request` looks up the victim's `Shipit::PullRequest` by `number` + resolved `repository.id`, and `#process` calls `pull_request.update(github_pull_request: params.pull_request)` unconditionally when a match is found. [6](#0-5) 

Root cause: the field used to pick the verification key (`repository.owner.login`) and the field used to pick the mutation target (`repository.full_name`) are two independently attacker-controlled JSON leaves in the same unauthenticated request body, and the code never verifies that the successfully-verified organization actually owns the repository being mutated. `verify_webhook_signature`'s `return true unless webhook_secret` (`lib/shipit/github_app.rb:77`) makes this trivial whenever any configured organization lacks a `webhook_secret` — the attacker simply names that organization in `repository.owner.login` while pointing `repository.full_name` at the victim.

None of the existing guards catch this: `drop_unhandled_event` only checks the event type exists a handler; `ExplicitParameters` schema on `EditedHandler` only requires `repository.full_name` to be a `String`, it performs no cross-field validation against the owner used for verification; there is no `force_github_authentication`, `User#authorized?`, or `require_permission!` in this unauthenticated webhook path (webhooks are inherently unauthenticated by design, relying solely on HMAC verification, which this bug defeats).

### Impact Explanation
An unprivileged internet attacker can mutate an arbitrary tracked `Shipit::PullRequest` row (title, state, and other fields serialized from `github_pull_request`) belonging to any organization/repository configured in Shipit, as long as they can name any organization in the multi-org `secrets.yml` github config that lacks a `webhook_secret` (or, more broadly, whose secret they know), to satisfy verification, while the `repository.full_name` field targets the victim repo/PR. This is a payload for one organization/repository mutating another organization's row with no authenticated actor in between, matching the Critical "payload for one repository mutating another's stack/commit/task" category. The attack is fully repeatable against any repository/PR number that Shipit tracks, across tenants sharing the same Shipit host.

### Likelihood Explanation
Requires only that the Shipit instance is configured in multi-organization mode (`Shipit.github_organizations` yielding multiple keys) with at least one organization's `webhook_secret` absent — a realistic and documented configuration state (`config/secrets.development.shopify.yml` shows multiple orgs each with `webhook_secret: # nil` as a template). [7](#0-6)  The attacker needs no credentials, session, or secret — only the ability to POST arbitrary JSON with a crafted `X-Github-Event: pull_request` header to `/webhooks`, and knowledge of a target `PullRequest` number, which is public GitHub information for public repositories.

### Recommendation
Enforce that the organization used to verify the signature matches the organization that owns the repository referenced by the payload before dispatching to handlers — e.g., after `verify_signature`, derive `repository_owner` and compare it against `Repository.from_github_repo_name(params.dig('repository','full_name'))&.owner`, rejecting the request (422) on mismatch. Additionally, do not allow `verify_webhook_signature` to silently return `true` when no `webhook_secret` is configured for an organization in multi-org mode; require an explicit, intentional opt-out per organization instead of silent bypass.

### Proof of Concept
minitest, `ActionDispatch::IntegrationTest` (or `ActionController::TestCase` matching existing `WebhooksControllerTest` style):
1. Configure/stub `Shipit.github_organizations` to include `'org-attacker'` and `'org-victim'`; stub `Shipit.github(organization: 'org-attacker')` to return a `GitHubApp` built with `webhook_secret: nil` (so `verify_webhook_signature` returns `true` unconditionally per `lib/shipit/github_app.rb:76-77`).
2. Create `repository = Repository.create!(owner: 'org-victim', name: 'repo')`, a `Stack` for it, and a `Shipit::PullRequest` with a known `number` and original `title`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, body: `{"action":"edited","number":<that number>,"pull_request":{...,"title":"ATTACKER TITLE",...},"repository":{"owner":{"login":"org-attacker"},"full_name":"org-victim/repo"},"sender":{"login":"attacker"}}`.
4. Assert response is `:ok` (200), and assert `pull_request.reload.title == "ATTACKER TITLE"` — proving both sides of the equality (`repository_owner == 'org-attacker'` used for verification, `repository.full_name`'s owner `== 'org-victim'` used for mutation) diverge while the mutation still succeeds.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-61)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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
