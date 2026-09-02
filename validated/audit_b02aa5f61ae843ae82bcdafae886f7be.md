### Title
Webhook signature is verified against the payload's `repository.owner.login`/`organization.login`, but event handlers act on the (unauthenticated) `repository.full_name` field — allowing a valid webhook signer for org A to trigger repository/stack actions for org B - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives *which organization's* `webhook_secret` to validate the HMAC against from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). Once the signature check passes, the full, unconstrained JSON `params` are handed to `Shipit::Webhooks.for_event(event)` handlers. Every handler resolves the `Stack`/`Repository` to act on from a *different* field of the same payload: `payload.dig('repository', 'full_name')` in `Handler#repository_name`. Nothing ties `repository.full_name`'s owner back to the `repository.owner.login`/`organization.login` value that was actually authenticated.

### Finding Description
- `verify_signature` selects the GitHub App config to check the signature with using an owner/org login taken straight out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

- `Shipit.github(organization: repository_owner)` and `GithubApp#verify_webhook_signature` look up per-organization configuration (each org has its own `webhook_secret`): [3](#0-2) [4](#0-3) 

- After the signature is accepted for organization X, the handler dispatch passes the entire raw `params` (untouched) to every registered handler for the event: [5](#0-4) 

- Handlers resolve which `Stack`s to mutate using `repository.full_name`, a field that was never checked against the owner/org used for signature verification: [6](#0-5) [7](#0-6) 

The binding that should hold is: `organization authenticated (repository.owner.login used for HMAC lookup) == repository actually written (repository.full_name used to load Stack/Repository)`. Nothing in the codebase enforces this equality. Since `repository.owner.login`/`organization.login` and `repository.full_name` are independent keys inside the same signed JSON body, and the signature only covers "was this byte string signed by org X's secret," an entity that legitimately controls org A's webhook configuration (e.g. can trigger/redeliver a webhook for a repo it owns in org A) can construct a payload where `repository.owner.login` (or `organization.login`) = `A` (so it validates against A's `webhook_secret`) while `repository.full_name` = `B/some-repo`, a repository belonging to an entirely different organization `B` that also has a Stack registered in this Shipit instance.

### Impact Explanation
Because `verify_signature` only authenticates "signed by org A," but the handler acts on `repository.full_name`, an org-A-controlled webhook can:
- Invoke `PushHandler` to force `stack.sync_github(expected_head_sha: ...)` against a Stack that belongs to org B's repository, using an attacker-chosen `ref`/`after` SHA [8](#0-7) .
- Invoke `StatusHandler` to inject/forge a commit status against a commit belonging to org B's stack, tricking Shipit's own CI-gating logic (`ci.require`) into treating an untested commit as deployable/ready, potentially leading to an unauthorized deploy on org B's stack.
- Invoke `MembershipHandler`, `CheckSuiteHandler`, and pull-request handlers similarly cross-organization, since none of them re-validate `repository.owner` against the authenticated org.

This crosses the "cross-repository writes" / "unauthorized deploy" boundary called out as in-scope critical/high impact, achieved purely by an entity that only has legitimate signing capability for one organization's webhook (not general Shipit repository write access or an `ApiClient` token).

### Likelihood Explanation
Requires the attacker to be able to produce a validly-signed webhook body for *some* organization onboarded to this Shipit instance (e.g., control of a repo/webhook config in that org, or ability to trigger/redeliver a webhook event with edited content for that org via GitHub's UI/API), and requires that a second, distinct organization/repository also has a Stack configured in the same Shipit instance — a common deployment pattern for shared internal Shipit installations serving many teams/orgs. No Shipit session, `ApiClient` token, or GitHub App private key is needed; only legitimate webhook-trigger ability for one onboarded org.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, after signature verification, assert that the organization/owner used to select the `webhook_secret` (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` before dispatching to handlers; reject (422) any payload where these disagree.

### Proof of Concept
1. Shipit instance is configured with two organizations, `org-a` and `org-b`, each with its own `github_app` config/`webhook_secret`, and each has at least one `Stack` (e.g. `org-a/repo-a` and `org-b/repo-b`).
2. An actor who can produce a validly HMAC-signed webhook for `org-a` (e.g. via GitHub's webhook "redeliver" against a repo they administer in `org-a`, editing the payload before signature computation, or simply controlling the webhook delivery pipeline for `org-a`) crafts:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/repo-b"
  }
}
```
3. POST this to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature` computed with `org-a`'s `webhook_secret`.
4. `verify_signature` resolves `repository_owner` = `"org-a"`, looks up `Shipit.github(organization: "org-a")`, and the signature validates successfully [9](#0-8) .
5. `PushHandler.call(params)` resolves `repository_name` from `payload.dig('repository', 'full_name')` = `"org-b/repo-b"`, loads `org-b`'s stacks, and calls `stack.sync_github(expected_head_sha: params.after)` on them [10](#0-9) [8](#0-7)  — an org-b stack is mutated using data authenticated only for org-a.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
