This confirms multi-tenant support: `Shipit.github_app_config(organization)` looks up a per-organization config block (each with its own `webhook_secret`) keyed by GitHub org name [1](#0-0) , and `Shipit.github(organization:)` instantiates a distinct `GitHubApp` per organization key [2](#0-1) . This validates the binding-break analog described below.

### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the write target is resolved from a separately-trusted `repository.full_name` field, allowing cross-repository writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-tenant Shipit deployment, each GitHub organization onboarded to the instance has its own `webhook_secret` configured under `secrets.github[organization]` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to check the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` [3](#0-2) [4](#0-3) . Once the signature passes, `create` hands the *entire* raw JSON payload to the matching handlers [5](#0-4) . Those handlers, however, resolve which `Repository`/`Stack` to act on using a *different* field of the same payload: `payload.dig('repository', 'full_name')` [6](#0-5) , e.g. in `PullRequest::OpenedHandler#repository` [7](#0-6) .

### Finding Description
The trust binding that should hold is: **organization whose secret authenticated the HMAC == owner of the repository that is actually written to**. Nothing in the controller or in `Handler` enforces that `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the `Repository`/`Stack` to mutate) refer to the same repository/owner. An attacker who legitimately controls one onboarded GitHub organization/repo on the shared Shipit instance (and therefore knows *that org's* `webhook_secret`, since GitHub delivers it to them when they configure the webhook on their own repo) can craft an arbitrary raw POST body — HMAC-signed with their own org's secret — where `repository.owner.login` is set to their own org (so `verify_signature` passes) but `repository.full_name` is set to `"other-org/other-repo"` (so the handler resolves a `Stack` belonging to a completely different, unrelated onboarded repository) [4](#0-3) [6](#0-5) .

Before the attacker's crafted request: signature scope (org A) == write scope (org A's repos only), because GitHub only ever sends consistent payloads.
After the attacker's crafted request: signature scope (org A, verified) != write scope (attacker-chosen `full_name`, e.g. org B's repo), because the two fields are read independently from attacker-controlled JSON and never cross-checked.

This lets a webhook handler (e.g. `PullRequest::OpenedHandler`, `LabeledHandler`, `ClosedHandler`, etc., all of which trust `payload.dig('repository','full_name')` via the shared `Handler#stacks`/`#repository_name` helpers) create/mutate review stacks, labels, or merge/close state for a repository the attacker does not own, by forging cross-repository payload fields while only holding a signature secret for their own repository.

### Impact Explanation
This breaks the repository-ownership boundary between tenants sharing one Shipit instance: a party legitimately trusted only for their own repository's webhooks can trigger review-stack provisioning/state changes (`ReviewStackAdapter.find_or_create!`, label capture, PR close handling) against another organization's repository/stack records. This matches the "Critical - cross-repository writes" impact bucket, since it is an unauthorized write into a repository/stack outside the attacker's authenticated organization scope.

### Likelihood Explanation
Requires the attacker to be an onboarded org/repo owner on a shared Shipit instance (a real, if narrow, prerequisite — but such a party is otherwise a fully unprivileged outsider with respect to every other tenant's repositories). No Shipit user session, `ApiClient` token, or GitHub App private key is needed — only knowledge of their own repo's webhook secret, which GitHub hands them by design. The forged JSON body with mismatched `repository.owner.login` vs `repository.full_name` is trivial to construct.

### Recommendation
In `WebhooksController#create`/`verify_signature`, after determining the authenticating organization, enforce that every downstream reference to a repository (`repository.full_name`, `organization.login` used by handlers) is consistent with, or scoped to, the same authenticated organization before dispatching to handlers. Alternatively, have `Handler#repository_name`/`#stacks` validate that the resolved repository's owner matches the organization that authenticated the webhook signature, rejecting the payload otherwise.

### Proof of Concept
1. Attacker owns GitHub org `attacker-org` with repo `attacker-org/repo`, configured with webhook secret `S` on this shared Shipit instance (`secrets.github[:attacker-org][:webhook_secret] = S`).
2. Attacker crafts JSON body:
```json
{
  "action": "opened",
  "number": 1,
  "pull_request": { ... "head": {"sha": "...", "ref": "..."}, "user": {"login": "attacker"}, "assignees": [], "labels": [] },
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" },
  "sender": {"login": "attacker"}
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)` and POSTs to `/webhooks` with `X-Github-Event: pull_request`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates against secret `S` — passes [3](#0-2) .
5. `PullRequest::OpenedHandler#repository` resolves `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")` and provisions/mutates a review stack there, entirely outside the attacker's authenticated scope [8](#0-7) .

### Citations

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
