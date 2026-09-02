### Title
Webhook signature verified against `repository.owner.login` while handlers act on `repository.full_name` allows cross-organization forged webhook events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects the HMAC secret used to validate the `X-Hub-Signature` header based on `repository.owner.login` (or `organization.login`) taken from the JSON payload, while every webhook `Handler` resolves the repository/stack to act on using the entirely separate `repository.full_name` field from the same payload. Because both fields are attacker-controlled parts of the signed body, an org that legitimately possesses a valid webhook secret for its own organization can forge a payload whose `repository.owner.login` matches its own org (satisfying signature verification) but whose `repository.full_name` points at a different organization's repository, causing Shipit to sync commits, create statuses, and archive/unarchive/create review stacks for a repository that org never authenticated for.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization from the payload itself: [1](#0-0) 

and [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` and is used purely to pick which per-organization `webhook_secret` (from `Shipit.github(organization:)`, supporting the documented "Using Multiple Github Applications" configuration) is used to HMAC-verify the raw body.

However, once the signature check passes, every `Handler` subclass determines *which repository/stack to act on* using a different payload field, `repository.full_name`: [3](#0-2) 

This is used, for example, by `PushHandler` (triggers `stack.sync_github`): [4](#0-3) 

by the pull-request handlers that create/archive/unarchive Review Stacks and capture labels via `Repository.from_github_repo_name(params.repository.full_name)`: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` performs a plain lookup with no cross-check against any authenticated organization: [7](#0-6) 

The binding that should hold is: `organization authenticated by verify_signature == organization of the repository the handler writes to`. Instead, the code verifies `repository.owner.login` but writes based on `repository.full_name`, two independent, attacker-controlled strings inside the same JSON body. Any party that legitimately controls a GitHub App/webhook secret for *one* organization configured in Shipit's multi-org `secrets.yml` (as documented in `docs/setup.md`'s "Using Multiple Github Applications" section) can produce a validly-signed request (using their own known secret) whose `repository.full_name` names an arbitrary *other* organization's repository, causing Shipit to process the event as if it came from that other repository's GitHub App/organization.

### Impact Explanation
This breaks the "organization authenticated versus the repository that is written" trust binding explicitly called out as in-scope. In a multi-tenant Shipit instance, a party with legitimate webhook-secret knowledge for its own org can trigger cross-repository/cross-organization side effects it was never authorized for: forcing `GithubSyncJob`/`sync_github` on another org's stack, injecting fabricated commit statuses via `StatusHandler`/`commit.create_status_from_github!`, and creating, archiving, or unarchiving another org's Review Stacks and mutating their PR labels — all classified as unauthorized cross-repository writes.

### Likelihood Explanation
The webhook endpoint is a public, unauthenticated HTTP endpoint (no session, `ApiClient` token, or GitHub App private key required); the only requirement is knowledge of one legitimately-configured organization's `webhook_secret`, which any operator/GitHub App owner for that org already possesses by design in this multi-org configuration. No social engineering, TLS interception, or host misconfiguration beyond the explicitly documented multi-organization setup is required.

### Recommendation
Verify that `repository.full_name`'s owner matches (or is consistent with) the organization whose secret validated the signature (`repository_owner`) before dispatching to handlers, e.g., reject the webhook if `repository.full_name.split('/').first.casecmp(repository_owner) != 0`.

### Proof of Concept
1. Shipit is configured with multiple GitHub Apps, one per org, per `docs/setup.md`'s multi-org example — org `attacker-org` and org `victim-org` are both onboarded with distinct `webhook_secret`s.
2. An entity that legitimately knows `attacker-org`'s `webhook_secret` (e.g., that org's GitHub App admin) crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. It computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, body)` and POSTs to `/webhooks`.
4. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s secret, and the signature validates successfully.
5. `PushHandler#process` resolves the target stack via `Handler#repository_name` = `victim-org/victim-repo` (unrelated to `attacker-org`) and calls `stack.sync_github(expected_head_sha: ...)`, causing Shipit to process/deploy state changes for `victim-org`'s stack — despite the request only ever being authenticated for `attacker-org`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
