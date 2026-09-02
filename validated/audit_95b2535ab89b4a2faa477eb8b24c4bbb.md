### Title
Signature verification selects trust based on `repository.owner.login` while downstream handlers act on the unbound `repository.full_name` field, allowing cross-organization payload forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to validate a webhook against using `repository_owner`, a value read straight from the untrusted JSON body (`repository.owner.login` or `organization.login`). Once the signature check passes against *that* org's secret, the same raw payload is handed to `Shipit::Webhooks` handlers, which determine *which repository/stack to mutate* using a **different** field of the same payload: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb`). Nothing enforces that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` value that was used to select the verifying secret. This breaks the intended binding "organization whose secret authenticated the request == repository that gets written."

### Finding Description
`WebhooksController#verify_signature` does: [1](#0-0) [2](#0-1) 

`repository_owner` is computed purely from the attacker-supplied JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), and it is used to look up `Shipit.github(organization: repository_owner)`, which resolves to a per-organization `GithubApp` instance holding that organization's own `webhook_secret`: [3](#0-2) [4](#0-3) 

Shipit supports multiple independently-configured GitHub organizations on the same instance, each with its own `app_id`/`webhook_secret`/`private_key` (see the multi-org example in `config/secrets.development.shopify.yml`). Each org's administrators legitimately possess (or generate) that org's own `webhook_secret` when they set up their GitHub App.

After `verify_signature` succeeds, `WebhooksController#create` forwards the *same raw payload* to the handlers: [5](#0-4) 

The handlers, however, never re-check `repository.owner.login`; they resolve the target `Stack`/`Repository` solely from `repository.full_name`: [6](#0-5) 

Because `repository_owner` (used to select the trusted secret) and `repository.full_name` (used to select the repository actually written to) are two independent JSON fields inside the same body, and only the raw-body HMAC ties them together as a bundle — not to each other — an attacker who legitimately controls/knows one organization's `webhook_secret` (org A) can construct an arbitrary payload where `repository.owner.login`/`organization.login` = `"orgA"` (so the secret lookup and HMAC pass) but `repository.full_name` = `"orgB/some-repo"` (a completely different, unrelated organization/repository hosted on the same Shipit instance). The signature check has no knowledge of, and does not constrain, `full_name`.

This is directly analogous to the Caviar bug: the field acted upon (`recipient`/here, the actually-mutated repository) is not the field the security check is actually bound to (`royaltyFee` tally/here, `repository.owner.login` used for secret selection) — an accounting/trust inconsistency between "what was verified" and "what gets acted on."

### Impact Explanation
An attacker who is a legitimate (even low-privileged) member/owner of one onboarded GitHub organization on a shared, multi-org Shipit instance — and therefore knows/controls that org's `webhook_secret` — can forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are processed as if they originated from and pertain to a **different** organization/repository also hosted on the same instance. Depending on which handler is targeted this can drive `GithubSyncJob` to sync fabricated commits/branches into another org's stack, forge commit `status`/`check_suite` results that gate deploy eligibility, or manipulate `pull_request`/`membership` state for repositories/teams the attacker has no real GitHub permission over — i.e., a cross-repository write across an organizational trust boundary, and potentially an unauthorized deploy if fabricated green commit statuses/check runs are what gates the deploy in that stack's `shipit.yml`.

### Likelihood Explanation
Exploitation requires the attacker to already control a legitimate `webhook_secret` for at least one organization configured on the Shipit instance — realistic in any multi-tenant deployment (as the repo's own multi-org example config demonstrates) where each organization's admins independently register and hold their own GitHub App secret. No GitHub App private key, Shipit session, or `ApiClient` token is needed; only knowledge of one org's webhook secret and the ability to send an arbitrary HTTP POST to the public `/webhooks` endpoint with a matching HMAC over a body they fully craft.

### Recommendation
Bind the signature-selecting identity to the identity actually acted upon: after computing `repository_owner`, verify that `repository.full_name`'s owner segment (and/or `organization.login`) is identical to `repository_owner` before dispatching to handlers, or resolve/verify the target `Repository`/`Stack` record and assert its owner organization matches the organization whose secret validated the signature, rejecting (422) on mismatch.

### Proof of Concept
1. Shipit instance is configured with two organizations, `orgA` and `orgB`, each with its own `github.<org>.webhook_secret` (as shown in `config/secrets.development.shopify.yml`).
2. Attacker is a member of `orgA` and knows/controls `orgA`'s `webhook_secret` (e.g., because they set up `orgA`'s GitHub App).
3. Attacker crafts a `push` (or `status`/`check_suite`) JSON payload with:
   - `repository.owner.login` = `"orgA"`
   - `repository.full_name` = `"orgB/production-service"`
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "orgA")`, verifies the signature against `orgA`'s secret — it matches, so `head(422)` is not called. [1](#0-0) 
6. `create` dispatches the raw params to `Shipit::Webhooks.for_event('push')`, whose handler resolves the target stack via `payload.dig('repository', 'full_name')` = `"orgB/production-service"`, acting on `orgB`'s stack despite the request only being authenticated against `orgA`'s secret. [7](#0-6)

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
