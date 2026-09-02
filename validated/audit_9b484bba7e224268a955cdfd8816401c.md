## Title
Cross-organization webhook forgery: signature verification authenticates `repository.owner.login`, but event handlers act on the independently-attacker-controlled `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the untrusted, attacker-supplied JSON body. Once the signature check passes, `Shipit::Webhooks::Handlers::Handler#repository_name` (used by every handler, including `PushHandler`, the `pull_request` handlers, `MembershipHandler`, etc.) independently reads `repository.full_name` from the same body to decide which `Stack`/`Repository`/`Team` to act on. Because these are two separate, attacker-controlled fields inside one attacker-crafted JSON payload, an attacker who legitimately controls a GitHub App installation for organization A (and therefore knows/can compute A's webhook secret) can forge a payload whose `owner.login` is `A` (so the signature check passes using A's secret) but whose `full_name` names a completely different repository/stack `B/repo`, tracked under a different Shipit-configured organization.

### Finding Description [1](#0-0) 
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is: [2](#0-1) 

This chooses the HMAC secret purely from `repository.owner.login`/`organization.login` inside the JSON body being verified. Shipit supports multiple GitHub Apps/organizations, each with its own `webhook_secret`, resolved via `Shipit.github_app_config` / `Shipit.github`: [3](#0-2) 

After signature verification succeeds, `WebhooksController#create` dispatches the *same raw payload* to handlers: [4](#0-3) 

Every handler resolves the target repository/stack from `repository.full_name`, not from the field used for signature-org selection: [5](#0-4) 

This is used by `PushHandler` (triggers `stack.sync_github`) [6](#0-5) , and by the pull-request handlers (e.g. `ClosedHandler` archives review stacks) [7](#0-6) , and `label_capturing_handler.rb` [8](#0-7) .

`Repository.from_github_repo_name` simply splits and looks up by `owner`/`name` with no cross-check against which secret verified the request: [9](#0-8) 

**The broken binding (as an equality):** the engine implicitly assumes
`organization-that-authenticated-the-request == organization-that-owns-the-repository-being-acted-upon`.
In reality, both sides of that equality are read from independent, attacker-controlled JSON keys (`repository.owner.login` vs `repository.full_name`) inside the same forged HTTP body — nothing enforces they refer to the same repository. Before the attacker's request: only genuine GitHub-originated payloads exist, where these two fields are always consistent (GitHub itself sets both from the real event). After the attacker's request: the attacker supplies a payload where `owner.login = "attacker-org"` (whose secret they know because they legitimately installed a GitHub App / configured Shipit for their own org) while `full_name = "victim-org/victim-repo"` (a repository tracked by Shipit under a different organization's App), breaking the equality.

### Impact Explanation
This qualifies as **High** severity per the engine's rubric ("unauthenticated read of stack state" / cross-boundary write) — and arguably escalates further because it allows **unauthorized cross-repository writes**: an attacker who only controls/administers organization A's Shipit GitHub App configuration can:
- Forge `push` events to force `GithubSyncJob`/`sync_github` on an arbitrary tracked stack belonging to organization B, at attacker-chosen `expected_head_sha` [10](#0-9) .
- Forge `pull_request` `closed` events to archive review stacks belonging to organization B [11](#0-10) .
- Forge `membership` events, which create teams/users on the fly regardless of which org's secret was used (per test evidence) [12](#0-11) .

This is a genuine deployment-trust binding break, not merely a DoS/rate-limit issue, and does not require any Shipit session, `ApiClient` token, or GitHub App private key belonging to the victim org — only that Shipit is configured with more than one organization's GitHub App (a documented, supported configuration) and that the attacker controls one of them.

### Likelihood Explanation
Likelihood is **Medium-to-High** in any multi-organization Shipit deployment (explicitly documented and supported, see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`). Any org owner/admin with a legitimately configured Shipit GitHub App for their own organization can trivially craft this forged JSON body and compute a correct HMAC-SHA1 signature using their own known `webhook_secret`, since `verify_webhook_signature` only checks that the signature matches the raw body under the secret selected by the attacker-controlled `owner.login` field [13](#0-12) . In a single-organization deployment the impact is narrower (still same org, so less relevant), but the multi-org case is a fully supported, documented configuration.

### Recommendation
- Derive the organization used for webhook signature verification and the repository/stack targeted by the handler from the **same, single trusted field**, and reject the request if any per-event repository/organization reference is inconsistent with the verified organization.
- Alternatively, after selecting `github_app` by `repository_owner`, re-validate in `create`/`Handler#repository_name` that the resolved `Repository`'s `owner` matches the organization whose secret validated the signature, rejecting mismatches before invoking handlers.
- Consider using the GitHub `X-GitHub-Hook-Installation-Target-ID`/App installation metadata (if available) instead of body-derived fields for org selection, since installation IDs are not attacker-controlled JSON content in the way `repository.owner.login`/`full_name` are.

### Proof of Concept
Precondition: Shipit configured with `secrets.github` containing at least two organizations, e.g. `AttackerOrg` (attacker knows `webhook_secret`) and `VictimOrg` (tracks stack `victimorg/target-repo`), as supported by `Shipit.github_app_config` [14](#0-13) .

1. Attacker crafts JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "victimorg/target-repo"
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(AttackerOrg_webhook_secret, body)>` using their own known secret.
3. Attacker sends `POST /webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"AttackerOrg"`, fetches `Shipit.github(organization: "AttackerOrg")`, and the signature verifies successfully (attacker used the correct secret for that org) [1](#0-0) .
5. `PushHandler.call(params)` then resolves `stacks` via `repository_name` = `payload.dig('repository','full_name')` = `"victimorg/target-repo"` [15](#0-14)  and triggers `stack.sync_github(expected_head_sha: params.after)` on the victim organization's stack [10](#0-9)  — an unauthorized action on a repository the attacker's org never owned.

Note: I was unable to independently execute this PoC (no code execution available in this ask-only environment); the analysis above is based on static tracing of the code paths cited. A Devin session with repository access would be needed to run this as an actual integration test against the test fixtures (e.g. `test/fixtures/shipit/github_hooks.yml`, `test/dummy/config/secrets_double_github_app.yml`) to empirically confirm the forged cross-org signature bypass.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
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
