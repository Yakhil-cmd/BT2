### Title
Webhook signature verified against `repository.owner.login`, but event handlers act on `repository.full_name` - cross-organization/cross-repository write via forged webhook - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to check the `X-Hub-Signature` against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. The signature is a valid HMAC over the raw JSON body computed with *that organization's* `webhook_secret`, so it does authenticate "this body was produced by someone who knows orgA's webhook secret." However, every downstream handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, used transitively by `PushHandler`, all `PullRequest::*Handler`s, etc.) resolves the target `Repository`/`Stack` using a *different* field: `payload.dig('repository', 'full_name')`. Nothing ties `repository.owner.login` (the value used to select/verify the signing secret) to `repository.full_name` (the value used to decide which stack gets written to). A party who legitimately knows one organization's `webhook_secret` (the org they administer their own GitHub App for, in a multi-org Shipit deployment as documented in `config/secrets.development.example.yml`) can forge a JSON body whose `repository.owner.login` is their own org (so the signature check passes) while `repository.full_name` names a repository belonging to a completely different organization tracked by the same Shipit instance.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` resolves the GitHub App config strictly from `repository_owner`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

- The signature check itself just HMACs the raw body with whichever org's secret was selected: `GitHubApp#verify_webhook_signature` at [2](#0-1) . It proves only that the caller knows *that org's* secret — it makes no statement about which repository the payload's other fields describe.

- After signature verification, `create` blindly dispatches the entire parsed body to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .

- Every handler resolves its target repository/stack from `repository.full_name`, not from `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`Repository.from_github_repo_name` simply splits the string on `/` and does a DB lookup with no relation back to the signature-verified org: [5](#0-4) .

- Concrete handlers acting on that mismatched `full_name`-resolved repository/stack include:
  - `PushHandler#process`, which triggers `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the target branch: [6](#0-5) 
  - `PullRequest::OpenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, which call `stack.archive!`, `stack.unarchive!`, or auto-provision (`find_or_create!`) review stacks scoped to `repository.review_stacks` where `repository` is resolved purely from `params.repository.full_name`: [7](#0-6) [8](#0-7) 
  - `StatusHandler#process`, which writes a new commit status onto any `Commit` row matching the attacker-chosen `sha`, regardless of which repository that commit actually belongs to (commits are looked up globally by `sha`, with no repository scoping at all): [9](#0-8) 

- `docs/setup.md`/`config/secrets.development.example.yml` explicitly document that Shipit supports configuring **multiple GitHub organizations, each with its own `app_id`/`webhook_secret`**, on a single Shipit instance: [10](#0-9) . In that supported multi-tenant configuration, an org that legitimately owns and configured its own GitHub App (and therefore legitimately knows its own `webhook_secret`) is exactly the kind of "authenticated organization" the signature check trusts — but that trust does not extend to constrain which repository's stacks that org's payload is allowed to mutate.

**Binding broken**: `repository_owner` (the identity the HMAC signature authenticates) ≠ `repository.full_name` (the resource the handlers actually write to). The code implicitly assumes these two fields always agree because real GitHub-generated webhooks keep them consistent, but nothing in the engine enforces that invariant for a hand-crafted, validly-signed request.

### Impact Explanation
This is a cross-repository/cross-organization write: an entity trusted only for organization A's webhooks can trigger `sync_github` (which fetches from GitHub and can advance `continuous_deployment` stacks toward a deploy), archive/unarchive or auto-provision review-stacks, or inject fabricated commit statuses for any repository/stack tracked by the same Shipit instance under organization B — despite having no credentials, GitHub App installation, or webhook secret for organization B at all. This matches the "Critical - cross-repository writes / unauthorized deploy" impact category, since `sync_github`-triggered syncs on `continuous_deployment` stacks feed directly into the deploy pipeline, and status/webhook forgery can manipulate CI gating (`ci.require`) used to allow/block deploys.

### Likelihood Explanation
Exploitability requires the attacker to possess a valid `webhook_secret` for at least one organization configured in the Shipit instance. This is directly supported by the engine's own multi-org configuration model documented in `docs/setup.md`/`config/secrets.development.example.yml`, where separate organizations register their own GitHub Apps (and thus separately know their own secret) while sharing one Shipit deployment. This is a realistic, in-scope threat model for any Shipit installation serving more than one organization — it does not require compromising the deploy host, TLS interception, or an `ApiClient`/session token, only a credential the attacker is legitimately meant to have for their *own* organization.

### Recommendation
Bind the signature-verification identity to the resource-resolution identity: after selecting `github_app` via `repository_owner`, re-derive the repository from the *same* field used for verification (or verify that `repository.full_name`'s owner segment equals `repository_owner`) before dispatching to handlers. Reject the webhook (422) if the two disagree. More generally, `Handler#repository_name`/`Repository.from_github_repo_name` should never be trusted for authorization decisions independent of what was actually verified in `verify_signature`.

### Proof of Concept
Given a Shipit instance configured with two organizations, `orgA` (secret `SECRET_A`, attacker-administered) and `orgB` (secret `SECRET_B`, victim, with a `continuous_deployment` stack `orgB/victim-repo`):

1. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(SECRET_A, raw_body)>` using their own, legitimately-known `SECRET_A`.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` → `"orgA"`, loads `Shipit.github(organization: "orgA")`, and the HMAC check passes (attacker knows `SECRET_A`).
5. `create` dispatches to `PushHandler`, whose `stacks` resolves via `repository_name = "orgB/victim-repo"`, matching the victim's real stack, and calls `stack.sync_github(expected_head_sha: params.after)` on it — an org-A-authenticated request has mutated org B's stack state.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L59-68)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
