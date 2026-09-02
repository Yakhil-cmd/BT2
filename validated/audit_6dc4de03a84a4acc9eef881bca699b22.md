### Title
Webhook signature keyed on `repository.owner.login` while every event handler acts on `repository.full_name` — cross-organization forged webhook events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against using `repository_owner`, a value read directly out of the unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`). Every webhook handler, however, resolves the *actual* repository/stack to mutate using a different field of the same payload: `repository.full_name` (`Shipit::Webhooks::Handlers::Handler#repository_name` / `Repository.from_github_repo_name`). Because the field used to pick the verification key is not bound to the field the business logic trusts, an attacker who legitimately controls one configured GitHub organization in a multi-org Shipit deployment can forge a validly-signed webhook payload that names any other organization's repository in `repository.full_name`, bypassing the intended per-organization webhook trust boundary.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb:24-49` verifies the signature like this: [1](#0-0) 

`repository_owner` is derived purely from attacker-controlled JSON: [2](#0-1) 

`Shipit.github(organization:)` looks up a **separate `webhook_secret` per organization** when multiple GitHub Apps are configured (see `test/dummy/config/secrets_double_github_app.yml`, and `lib/shipit.rb`'s `github`/`github_app_config`): [3](#0-2) 

So the signature is verified with whatever secret corresponds to `repository.owner.login`/`organization.login` in the payload — a value the attacker fully controls and can set to their own organization.

After signature verification passes, the full, unmodified `params` object (not scoped to `repository_owner`) is dispatched to every registered handler for the event: [4](#0-3) 

All handlers, however, resolve the target repository/stack from a **different key** in the same payload — `repository.full_name` — via `Shipit::Webhooks::Handlers::Handler#repository_name` / `#stacks` and `Repository.from_github_repo_name`: [5](#0-4) [6](#0-5) 

For example `PushHandler` triggers a GitHub sync for whatever stacks match `repository.full_name`/branch: [7](#0-6) 

This is the same class of bug as the `_owners` shadowing report: the value the security check is bound to (`repository.owner.login`, used to pick the verifying key) is not the same value the privileged operation trusts (`repository.full_name`, used to pick the target repository). The report's "verified mapping" vs. "used mapping" mismatch is directly analogous to "an organization that authenticated versus the repository that is written" — one of the explicitly recognized binding classes for this engine.

### Impact Explanation
In a multi-organization Shipit deployment (the documented `secrets.github.<org>` schema, exercised by `test/dummy/config/secrets_double_github_app.yml`), each organization has its own `webhook_secret`. Any actor who legitimately owns/administers one configured organization (e.g., they installed the Shipit GitHub App on their own account/org, which is a normal, unprivileged onboarding action, not a Shipit credential) can compute a valid HMAC using their own secret over a forged payload whose `repository.owner.login`/`organization.login` is their own org, but whose `repository.full_name` names a stack belonging to a *different* configured organization/repository. `verify_signature` accepts the signature (it only checked their own org's secret against their own org's claimed identity), and the handler dispatch then acts on the victim repository. This lets the attacker:
- Inject fabricated `push` events (`PushHandler`) causing `GithubSyncJob` to run against a victim stack's real GitHub repo (using the victim's own `GITHUB_TOKEN`/installation, since `Stack#github_api`/`Repository#github_app` looks up credentials from the real `Repository.owner`, not from the attacker), potentially importing/creating fake commit records tied to shas the attacker controls, feeding continuous-deployment logic.
- Inject fake `status`, `check_suite`, `pull_request` (open/close/label/assign) events against victim stacks, manipulating CI gating, merge-queue provisioning/archival logic, and PR labels for repositories they do not own.
- Create/close/manipulate review stacks (`ReviewStackAdapter`) on a victim's repository.

This is a cross-repository/cross-organization write achieved without any Shipit session, `ApiClient` token, or the victim organization's actual `webhook_secret` — matching the Critical "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires the host to be configured with the documented multi-organization `github:` schema (more than one organization's webhook secret configured in the same Shipit instance) and requires the attacker to control (or become) one of those onboarded organizations — a realistic scenario for any Shipit instance that serves multiple teams/orgs, which is exactly the use case the multi-org config schema exists for. No other credentials, sessions, or privileged access are required; only network access to the public `/webhooks` endpoint and the ability to compute an HMAC-SHA1 with a secret the attacker already legitimately possesses.

### Recommendation
Bind the signature-verification key selection and the payload's operative repository/organization to the *same, single* trusted field, and reject the payload if they diverge:
1. In `WebhooksController#verify_signature`, after determining `repository_owner`, additionally verify that the value used to select the app config matches the organization/owner of `repository.full_name` used later by the handlers (i.e., derive both from `repository.full_name.split('/').first`, not from a separate `owner.login`/`organization.login` field).
2. Alternatively/additionally, once a `github_app`/organization has been authenticated for the request, pass that authenticated organization identity down to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params, authenticated_organization:) }` and have each handler assert `repository.owner` (or `full_name`'s owner segment) equals the authenticated organization before resolving/mutating any `Repository`/`Stack`.
3. Add regression tests asserting that a validly-signed webhook whose `repository.full_name` owner differs from the organization/secret used to sign it is rejected.

### Proof of Concept
Preconditions: Shipit instance configured with multi-org `github:` schema, e.g. `OrgA` (attacker-controlled/owned) and `OrgB` (victim), each with distinct `webhook_secret`s, both matching `test/dummy/config/secrets_double_github_app.yml`'s shape.

1. Attacker legitimately obtains `OrgA`'s `webhook_secret` (e.g., they created/administer the GitHub App installation for `OrgA` themselves).
2. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefcafefeed0000000000000000000000",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner` = `"OrgA"`, loads `Shipit.github(organization: "OrgA")`, verifies the HMAC successfully (it is indeed valid for `OrgA`'s secret over this exact body).
6. `create` then calls `Shipit::Webhooks.for_event('push')` → `PushHandler.call(params)`. `PushHandler#stacks` resolves via `Repository.from_github_repo_name("OrgB/victim-repo")`, matching real stacks under `OrgB`, and enqueues `GithubSyncJob` against `OrgB`'s stack with attacker-supplied `expected_head_sha`, despite the request never being signed by `OrgB`.

(Full working forge script and exact byte-for-byte HMAC computation would need to be validated in a running instance with real fixtures — this was reasoned from the code paths cited above and not executed against a live deployment.)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
