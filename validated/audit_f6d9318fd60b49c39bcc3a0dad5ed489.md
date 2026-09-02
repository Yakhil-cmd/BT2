### Title
Signature verification keyed off an attacker-controlled org while the acted-upon repository is a different field of the same unsigned payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `webhook_secret` to validate the HMAC against using `repository_owner`, a value read straight out of the *unverified* JSON body, before the signature has been checked. Every downstream handler then acts on a different field of that same unverified body — `repository.full_name` — to look up the `Repository`/`Stack` to mutate. Nothing ties these two fields together, so the "organization whose secret authenticated the request" is not provably the "repository being written to."

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end
``` [1](#0-0) 

This uses `repository.owner.login` — a JSON field fully controlled by whoever sends the POST — to pick the HMAC secret (`Shipit.github(organization: ...)` looks up per-org `webhook_secret` config, see `app/models/shipit/repository.rb:100-102` and `lib/shipit/github_app.rb:44-50,76-83`) [2](#0-1) [3](#0-2) . The HMAC itself only proves the raw body was signed by *some* org's secret; it says nothing about which org that secret belongs to except via this same untrusted `repository.owner.login` value used to pick the verifier.

Once `verify_signature` passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3)  dispatches to handlers such as `PushHandler` and `PullRequest::ClosedHandler`, all of which resolve the target `Repository`/`Stack` via `payload.dig('repository', 'full_name')` (base `Handler#repository_name`) [5](#0-4) , or an equivalent `params.repository.full_name` lookup in the pull-request handlers [6](#0-5) . `Repository.from_github_repo_name` splits this string on `/` and does an unscoped `find_by(owner:, name:)` [7](#0-6)  — it never cross-checks that this owner equals the `repository.owner.login`/`repository_owner` value that selected the signing secret.

Because `repository.owner.login` and `repository.full_name` are two independent strings in the same untrusted JSON body, an attacker who legitimately controls a GitHub App installation on Organization A (and thus knows/can trigger a validly-signed webhook secret for A) can craft a POST where `repository.owner.login == "org-a"` (so `verify_signature` selects org A's secret and the HMAC — computed over the attacker-chosen raw body — validates), while `repository.full_name == "org-b/some-repo"` points at a completely different, victim organization's stack. The equality that should hold — "organization whose secret authenticated the request" == "repository owner whose stack the handler mutates" — is broken.

### Impact Explanation
Reachable, unprivileged-attacker exploitation depends on the attacker being able to produce a validly-signed webhook body for *any* org configured in Shipit (e.g., their own org, or one they have push access to), which is the normal, documented way GitHub delivers `push`/`pull_request` events — no Shipit session or API token is required, satisfying the "unprivileged attacker" bar. If achievable, this allows cross-organization/cross-repository mutation: e.g. `PushHandler` triggers `stack.sync_github(expected_head_sha:)` [8](#0-7)  against a stack that belongs to a different, victim GitHub organization than the one whose signature was actually verified, and `PullRequest::ClosedHandler` can archive a victim org's review stack [9](#0-8) . This matches the in-scope "cross-repository writes" / "unauthorized deploy" impact class.

### Likelihood Explanation
Moderate-to-low confidence overall: exploitability is contingent on operational specifics not fully visible from static review — specifically, whether `Shipit.github(organization: repository_owner)` can resolve to an org whose secret the attacker actually knows for a `repository.owner.login` value they control, and whether any Rails-level GitHub webhook IP allowlisting or additional per-repo checks exist elsewhere in the deployment that aren't part of this engine's own code. In a genuinely multi-tenant Shipit instance backing several unrelated GitHub organizations, this is directly triggerable by anyone with push access to any one of the configured orgs.

### Recommendation
After verifying the signature, re-derive the repository/organization strictly from the *same* field used to select the secret (or verify that `repository.full_name.split('/').first == repository_owner`) before dispatching to handlers, and have `Handler#repository_name`/`Repository.from_github_repo_name` reject repositories whose owner doesn't match the organization that authenticated the request.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1 over raw body using ORG-A's webhook_secret>

{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": {"login": "org-a"},
    "full_name": "org-b/victim-repo"
  }
}
```
`verify_signature` selects `Shipit.github(organization: "org-a")` and validates the HMAC successfully (attacker knows org-a's secret because they legitimately control org-a). `PushHandler` then resolves `Repository.from_github_repo_name("org-b/victim-repo")` and calls `sync_github` on any matching stacks belonging to `org-b`, an organization whose secret was never checked.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
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
