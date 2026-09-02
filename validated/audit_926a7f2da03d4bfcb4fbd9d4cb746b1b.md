Based on my investigation, I found a genuine analog to the reported bug class in `WebhooksController`.

### Title
Webhook signature verification is bound to the attacker-controlled `repository.owner.login`, not the repository actually mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The Bunni bug is about a value used for a security-relevant check (slippage/hooklet) being taken from a stale variable that no longer matches the value actually acted upon. The same class of bug exists in `WebhooksController#verify_signature`: the GitHub App/organization whose `webhook_secret` is used to **verify** the HMAC signature is selected from an attacker-controlled field of the *unverified* JSON body, while the repository/stack that is actually **written to** (via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) is selected from a different field of that same unverified body.

### Finding Description
`WebhooksController` runs `verify_signature` as a `before_action`: [1](#0-0) 
`repository_owner` (the binding used to pick which `GitHubApp`/secret to verify against) is read directly from the untrusted, unverified request body: [2](#0-1) 

`Shipit.github(organization: ...)` looks up per-organization config, and `verify_webhook_signature` explicitly treats a missing/blank `webhook_secret` as automatically verified: [3](#0-2) [4](#0-3) 

Once `verify_signature` passes, `create` re-parses the *same* attacker-controlled body and dispatches it to handlers such as `PushHandler`, which selects the `Stack`(s) to mutate using a completely different field of the payload (`branch`, derived from `params.ref`) and, via the shared `Handler` base, matches stacks by `repository.full_name`, not by `repository.owner.login`: [5](#0-4) 

So the equality that should hold is:
`organization used to select webhook_secret for signature verification == organization/repository that the handler actually writes to`

This equality can be broken: in a multi-organization Shipit deployment (`config/secrets.yml` with a `github` section keyed by organization, as documented), if **any** configured organization has no `webhook_secret` set, `verify_webhook_signature` returns `true` unconditionally for a payload whose `repository.owner.login` (or `organization.login`) is set to that unsecured org's name — regardless of what `repository.full_name` is actually inside the body. Because the handlers key off `repository.full_name`/`branch` (not `repository.owner.login`), an attacker can craft a payload that:
- sets `repository.owner.login` to the organization that has no `webhook_secret` configured (bypassing signature verification entirely), while
- sets `repository.full_name`/`ref`/`after` to point at a stack belonging to a *different, properly-secured* organization's repository.

This is documented as normal in `docs/setup.md` ("Webhook secret (optional)"), but the security consequence — that an unsecured org's identity can be used to forge webhook events (fake pushes, fake commit statuses, fake check-suite results) for any other repository/stack tracked by the same Shipit instance — is not addressed anywhere in the engine's code.

### Impact Explanation
An unauthenticated, unprivileged external attacker (no Shipit session, no `ApiClient` token, no `webhook_secret`) can forge `push`, `status`, or `check_suite` webhook events for any stack tracked by the Shipit instance, as long as the multi-org configuration includes at least one organization without a `webhook_secret`. This can:
- Inject fabricated commits into a stack's history via `GithubSyncJob`, or
- Forge CI `status`/`check_run` results consumed by `MergeRequest#all_status_checks_passed?`/`StatusChecker`, which gates automatic merges and continuous deployment.

Forged CI statuses feeding the merge queue can lead to an **unauthorized merge/deploy** of code that hasn't actually passed CI — matching the "unauthorized deploy, rollback or merge" Critical impact category, since it corrupts the source-of-truth signal (`Commit#statuses`) that downstream automatic merge/deploy logic relies on for a repository the attacker has no legitimate access to.

### Likelihood Explanation
Likelihood is Medium: it requires a specific configuration (multiple GitHub organizations configured under `github`, with at least one lacking a `webhook_secret`), which the setup docs explicitly present as a supported, "optional" configuration rather than a misconfiguration. Any installation following that documented multi-org setup while leaving even one org's `webhook_secret` blank is exposed, and the webhook endpoint requires no authentication to reach.

### Recommendation
Do not let `repository_owner` (used purely to pick a signing secret) implicitly authorize the repository/stack that the parsed payload is applied to. Concretely:
- Verify the signature using the secret associated with the organization that actually owns the target repository/stack resolved by the handler (i.e., resolve `repository.full_name` to a `Stack`/`Repository` first, derive its organization, and use that organization's secret), rather than trusting the payload's self-reported `repository.owner.login`/`organization.login`.
- Alternatively, require `webhook_secret` to be present for every configured organization and refuse to boot/serve webhooks for any organization lacking one, removing the `return true unless webhook_secret` bypass in `lib/shipit/github_app.rb`.

### Proof of Concept
1. Configure Shipit with two organizations in `config/secrets.yml`: `orgA` (no `webhook_secret` set) and `orgB` (has a `webhook_secret`, and owns a real tracked `Stack`, e.g. `orgB/app`).
2. Send an unauthenticated `POST /webhooks` with header `X-Github-Event: push` and no/garbage `X-Hub-Signature`, with a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/app" }
}
```
3. `repository_owner` resolves to `orgA`; `Shipit.github(organization: "orgA")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of the (missing/invalid) signature header.
4. `create` parses the same body and dispatches to `PushHandler`, which looks up stacks by `branch` (`main`) across `Shipit::Stack`; combined with `full_name: "orgB/app"` used elsewhere in the pipeline (e.g. `status`/`check_suite` handlers matching by `repository.full_name`), the attacker injects a forged event against `orgB/app`'s stack without ever knowing `orgB`'s webhook secret. [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-63)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
  end
```

**File:** lib/shipit/github_app.rb (L1-83)
```ruby
# frozen_string_literal: true

module Shipit
  class GitHubApp
    class Token
      class << self
        def from_github(github_response)
          new(github_response.token, github_response.expires_at)
        end
      end

      attr_reader :expires_at, :refresh_at

      def to_s
        @token
      end

      def initialize(token, expires_at)
        @token = token
        @expires_at = expires_at

        # This needs to be lower than the token's lifetime, but higher than the cache expiry setting.
        @refresh_at = expires_at - GITHUB_TOKEN_REFRESH_WINDOW
      end

      def blank?
        # Old tokens missing @refresh_at may be used upon deploy, so we should auto-correct for now.
        # TODO: Remove this assignment at a later date.
        @refresh_at ||= @expires_at - GITHUB_TOKEN_REFRESH_WINDOW
        @refresh_at.past?
      end
    end

    DOMAIN = 'github.com'
    AuthenticationFailed = Class.new(StandardError)
    API_STATUS_ID = 'brv1bkgrwx7q'

    GITHUB_EXPECTED_TOKEN_LIFETIME = 60.minutes
    GITHUB_TOKEN_RAILS_CACHE_LIFETIME = 50.minutes
    GITHUB_TOKEN_REFRESH_WINDOW = GITHUB_EXPECTED_TOKEN_LIFETIME - GITHUB_TOKEN_RAILS_CACHE_LIFETIME - 2.minutes

    attr_reader :oauth_teams, :domain, :bot_login

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

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
