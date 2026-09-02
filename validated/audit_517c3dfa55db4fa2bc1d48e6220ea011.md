### Title
Webhook event forgery via decoupled organization-authentication and repository-target fields when `webhook_secret` is unset - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App config (and therefore which `webhook_secret`) to check the signature against using a field pulled straight out of the **unverified** JSON body (`repository.owner.login` / `organization.login`), and `GitHubApp#verify_webhook_signature` unconditionally returns `true` whenever that selected config has no `webhook_secret` configured. Once past that gate, every registered webhook handler acts on a *different*, unrelated field of the same unverified payload — `repository.full_name` — to pick the target `Repository`/`Stack`. Nothing binds "the organization whose credential material gated the request" to "the repository the handler will act on."

### Finding Description
`verify_signature` derives the org used to select the signing secret from attacker-controlled JSON, before any cryptographic check occurs: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` treats a blank/unconfigured `webhook_secret` as "always valid": [3](#0-2) 

The rest of the pipeline hands the full, still-unverified `params` to every handler registered for the event: [4](#0-3) 

Every handler then resolves its target stacks from a *separate* field of the same payload, `repository.full_name`, with no cross-check against the `repository_owner`/`organization.login` value that was used to pick the signing secret: [5](#0-4) [6](#0-5) 

This breaks the intended equality: `organization authenticated (repository_owner used to select webhook_secret) == owner(repository acted upon, repository.full_name)`. If any configured org in `Shipit.secrets.github` (multi-org mode) has no `webhook_secret`, or if the whole install has none configured (`secrets.github[:webhook_secret]` absent, single-org mode via `Shipit.github`), the entire signature check degenerates to a no-op regardless of which repository/stack the attacker names in `repository.full_name`. An unauthenticated caller can then POST arbitrary JSON to the webhook endpoint and have it processed as a legitimate GitHub event for any repository present in the Shipit database, because `repository_owner` (used for the authentication decision) and `repository.full_name` (used for the target decision) are never required to agree, and the authentication decision itself can be trivially satisfied by an absent secret.

The blast radius is not limited to `push`: the test suite shows the `membership` handler creates `Team`, `User`, and `Membership` records purely from payload content: [7](#0-6) 

Since `User#authorized?` grants application access based solely on `teams.where(id: Shipit.github_teams.map(&:id))`, a forged `membership` event that names one of `Shipit.github_teams` and an attacker-controlled GitHub `login` creates a `Membership` binding that GitHub identity to an authorized team: [8](#0-7) 

### Impact Explanation
Under the "no webhook_secret configured" condition (a supported, non-privileged code path — not a credential the attacker must possess), this crosses the "organization authenticated vs. repository written" binding: an attacker with no Shipit session, no `ApiClient` token, and no GitHub credentials can:
- Forge `push`/`status`/`check_suite`/`deployable_status` events for **any** repository tracked by the instance, triggering `sync_github`, status changes, and CI-check refreshes on stacks they have no relationship to.
- Forge a `membership` event to inject their own GitHub login into a `Team` that satisfies `Shipit.github_teams`, escalating into the `Shipit.github_teams` authorization gate the moment they complete a normal OAuth login — a High-severity escalation per the impact rubric ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Exploitability depends entirely on whether the deployed instance's `secrets.github` (or a specific org's config in multi-org mode) has an empty/absent `webhook_secret`. This is a legitimate, code-supported state (`@config[:webhook_secret].presence`) rather than a documented hard requirement, so it is plausible in real deployments (e.g., staging/dev instances, or partially-configured multi-org setups where one org's secret was never set). The webhook endpoint itself requires no authentication of any kind, so once that condition holds, the rest of the chain (decoupled `repository_owner` vs. `repository.full_name`, and the membership handler's unchecked team/member assignment) is directly reachable by any unauthenticated network client.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub App/org; fail closed (reject the webhook) instead of returning `true` when it is blank, rather than treating an absent secret as "skip verification."
- Bind the organization used to select/verify the signing secret to the organization implied by every payload field the handlers subsequently act on (e.g., assert `repository.full_name`'s owner equals the `repository_owner`/`organization.login` used in `verify_signature`) before dispatching to handlers.
- For the `membership` handler specifically, only allow membership mutations for teams that are verifiably associated with the authenticated organization, not solely from payload content.

### Proof of Concept
1. Deploy (or identify) a Shipit instance where `secrets.github.webhook_secret` (or a specific org key in multi-org config) is unset.
2. POST to the webhooks endpoint with header `X-Github-Event: push` and a body where `repository.owner.login` is set to that unsecured org, but `repository.full_name` names a completely different, unrelated tracked repository/stack (e.g., a production stack).
   - `verify_signature` selects the unsecured org's `GitHubApp`, whose `verify_webhook_signature` returns `true` unconditionally regardless of the `X-Hub-Signature` header value.
   - `PushHandler` then resolves stacks via `repository.full_name` and calls `stack.sync_github(expected_head_sha: params.after)` on the unrelated, victim stack.
3. Repeat with `X-Github-Event: membership`, `action: added`, `member.login` set to an attacker-controlled GitHub login, and `team` matching one of `Shipit.github_teams`, to create a `Membership` granting that login application authorization (see `test/controllers/webhooks_controller_test.rb:142-149` for the exact payload shape the handler accepts).

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```

**File:** test/controllers/webhooks_controller_test.rb (L129-149)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
