### Title
Webhook signature is verified against the wrong organization's secret, letting an attacker with one org's webhook credentials forge events for repositories of other configured organizations - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC against using an attacker-controlled field of the *same, unverified* payload, while the handlers that actually act on the payload key their target `Repository`/`Stack` off a *different* field of that payload. The two fields are never cross-checked, so in a multi-organization Shipit deployment the org that "authenticates" the request is not guaranteed to be the org whose repository is mutated.

### Finding Description
`verify_signature` picks the signing secret via: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')` (or `organization.login`) — a value taken straight from the untrusted JSON body, before any signature has been validated. `Shipit.github(organization: repository_owner)` looks up the per-organization `webhook_secret` from `config/secrets.yml`, which explicitly supports multiple orgs each with its own app/secret: [3](#0-2) 

The HMAC is computed over the entire raw body, so it does prove the request was signed by *some* configured organization's secret — but the code only checks that `X-Hub-Signature` matches the secret belonging to `repository.owner.login`, and never confirms that `repository.full_name`'s owner equals that same `repository.owner.login`, or that the target repository actually belongs to the organization whose secret produced the signature.

Downstream, every handler resolves the target repository/stack from a **different** payload field, `repository.full_name`, independent of `repository.owner.login`: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

**Binding that should hold:** `organization authenticated by X-Hub-Signature == organization owning repository.full_name acted upon`.
**What actually happens:** the code only enforces `organization authenticated == repository.owner.login` (a sibling field of the same unauthenticated JSON body), and separately uses `repository.full_name` (which can name an entirely different org/repo) to select the `Stack`/`Repository`/`Commit` acted upon. Nothing ties these two fields together.

### Impact Explanation
Given a Shipit instance configured with multiple GitHub organizations (as documented for multi-org setups), an attacker who controls a GitHub App/webhook installation for *their own* organization (i.e., knows/can compute a valid signature with their own `webhook_secret`, which is not a privileged Shipit credential — it's whatever secret they set when installing the App on their own org) can craft a payload where `repository.owner.login`/`organization.login` matches their own org (passing signature verification) while `repository.full_name` or `sha` in the same payload references a repository or commit belonging to a **different** organization also configured on the same Shipit instance. Handlers such as `PushHandler` would then call `stack.sync_github(expected_head_sha: ...)` on a foreign stack, `StatusHandler` would attach forged CI status results to a foreign commit (`Commit#create_status_from_github!`), and `PullRequest` handlers would archive/unarchive/create review stacks on a foreign repository — all cross-organization writes to state that gate deploy/merge eligibility, achieved purely by controlling a signature-valid payload for one's own org.

### Likelihood Explanation
This requires the operator to configure more than one GitHub organization/app in `config/secrets.yml` (a supported and documented configuration) and requires the attacker to control (or have compromised) the GitHub App installation of at least one of those organizations — not any Shipit application credential, GITHUB_TOKEN, or ApiClient token. No repository write access to the victim org and no Shipit session are required; only the ability to sign an HTTP POST with one's own org's `webhook_secret` and choose the JSON body content.

### Recommendation
In `WebhooksController#verify_signature`, after establishing which organization's secret validated the signature, re-derive `repository.full_name`'s owner and reject the event (422) unless it matches `repository_owner`/`organization.login` used for the lookup. Equivalently, have `Handler#repository_name`/`stacks` refuse to resolve a repository whose owner differs from the authenticated organization for that request.

### Proof of Concept
1. Configure two organizations, `org-a` and `org-b`, each with their own GitHub App and `webhook_secret`, on one Shipit instance (per `docs/setup.md` "Using Multiple Github Applications").
2. As the operator/attacker of `org-a`'s GitHub App, craft a `push` event payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "full_name": "org-b/victim-repo", "owner": { "login": "org-a" } }
   }
   ```
3. Sign the raw body with `org-a`'s `webhook_secret` and send it as `X-Hub-Signature`, `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner` = `"org-a"` and verifies successfully against `org-a`'s secret.
5. `PushHandler#stacks` resolves via `Repository.from_github_repo_name("org-b/victim-repo")`, and calls `sync_github(expected_head_sha: "<attacker-chosen sha>")` on `org-b`'s stack — a cross-organization write triggered without any credential belonging to `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
