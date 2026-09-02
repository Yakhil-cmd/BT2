### Title
Cross-repository webhook forgery via organization/repository binding mismatch in webhook signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which HMAC `webhook_secret`) to use for validating an inbound webhook based on `repository.owner.login` (or `organization.login`) extracted from the request body. However, the handler that actually acts on the payload (`Shipit::Webhooks::Handlers::PushHandler`, via `Handler#repository_name`) resolves the target `Repository`/`Stack` using a completely different field of the same payload: `repository.full_name`. In a multi-organization Shipit deployment (`config/secrets.yml` supporting a `github: { orgA: {...}, orgB: {...} }` schema), an attacker who legitimately controls a webhook secret for one onboarded organization can forge a payload that authenticates as their own org while writing to a stack belonging to a different org.

### Finding Description
The controller performs signature verification like this: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from `params.dig('repository', 'owner', 'login')`, and `Shipit.github(organization: repository_owner)` picks the `GitHubApp` instance (and its `webhook_secret`) used to compute/verify the HMAC: [3](#0-2) 

Once the signature is accepted, `WebhooksController#create` dispatches the raw JSON body to the registered handlers for the event, unmodified: [4](#0-3) 

The `PushHandler` (and the base `Handler` class shared by all other handlers, e.g. `pull_request/*`, `check_suite`, etc.) resolves which `Stack`s to operate on from `repository.full_name`, a field that is **not** the field used to select the verifying secret: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` performs no cross-check against the organization that was used to authenticate the request; it just splits `owner/name` out of `full_name` and looks up the row: [7](#0-6) 

Because the entire raw request body is HMAC-signed as one blob, and `repository.owner.login` and `repository.full_name` are independent JSON keys inside that same blob, an attacker who owns a legitimate `webhook_secret` for `orgA` (i.e., is an admin/maintainer of `orgA`'s GitHub App installation — an org that is deliberately onboarded to this Shipit instance, but has no privilege over `orgB`) can craft and correctly sign a payload where:
- `repository.owner.login = "orgA"` (or `organization.login = "orgA"`) — satisfies `verify_webhook_signature` using `orgA`'s secret, which the attacker legitimately possesses.
- `repository.full_name = "orgB/some-repo"` — is the value actually used by `PushHandler`/other handlers to look up and act on the target `Stack`.

This breaks the intended binding: **organization authenticated == organization whose repository is written**. The authenticated identity (`orgA`) and the written repository owner (`orgB`) diverge, letting an attacker trigger a `sync_github`/deploy job (`stack.sync_github(expected_head_sha:)`) against a repository/stack they were never authorized to interact with, without ever knowing `orgB`'s webhook secret. Handlers for `pull_request`, `check_suite`, `status`, `membership` are built on the same `Handler#repository_name`/`stacks` pattern (`app/models/shipit/webhooks/handlers/handler.rb`) and are equally exposed via the shared `full_name`-based repository resolution, so the class of exploitable actions is not limited to push-triggered syncs.

### Impact Explanation
This is an unauthorized cross-organization / cross-repository write: an actor holding valid credentials (a webhook secret) for one onboarded organization can force actions (e.g., queuing `GithubSyncJob`/deploy-triggering syncs) against stacks belonging to an entirely different organization hosted on the same Shipit instance, without possessing that organization's secret. This satisfies the "cross-repository writes" / "unauthorized deploy" criteria for a Critical-severity finding, since it crosses a trust boundary the signature check is specifically meant to enforce.

### Likelihood Explanation
Exploitability requires the attacker to already control a legitimate webhook secret for at least one org configured in this Shipit instance (a realistic scenario for any multi-tenant/multi-org deployment as explicitly documented and supported by `Shipit.github_app_config`/`config/secrets.yml`). No other privilege (no Shipit session, no API token, no repository write access on the target org) is needed — only the ability to send an HTTP POST to `/github_webhooks` with a validly-signed body for the attacker's own org. This is a realistic, low-effort attack for any customer of a shared multi-org Shipit deployment.

### Recommendation
Bind the field used to select the verifying webhook secret to the field(s) actually consumed by handlers. Concretely, after verifying the signature, re-derive `repository_owner` from the same `repository.full_name` (or `owner` in the resolved `Repository` record) that handlers use to select the target stack, and reject the payload if `repository.owner.login`/`organization.login` does not match the owner segment of `repository.full_name`. Alternatively, compute the verifying organization strictly from `repository.full_name.split('/').first` rather than `repository.owner.login`, so a single JSON key drives both the trust decision and the target-resolution logic.

### Proof of Concept
1. Deploy Shipit with a multi-org config in `config/secrets.yml`:
```yaml
github:
  orgA:
    webhook_secret: "secretA"
    ...
  orgB:
    webhook_secret: "secretB"
    ...
```
2. Attacker is a legitimate maintainer of `orgA`'s GitHub App and knows `secretA` (or can request GitHub to sign a payload for their own installation).
3. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled-sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(secretA, body)` and POSTs to `/github_webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, loads `Shipit.github(organization: "orgA")`, and successfully verifies the signature using `secretA` — [1](#0-0) .
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgB/victim-repo")` — [6](#0-5) [7](#0-6)  — and enqueues `stack.sync_github(expected_head_sha: <attacker-controlled-sha>)` against `orgB`'s stack, despite the request never being signed by `orgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
