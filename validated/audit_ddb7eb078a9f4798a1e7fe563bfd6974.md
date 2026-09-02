### Title
Webhook signature verified against the payload's `repository.owner.login` while the event handler dispatches on the independently-controlled `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization deployments (`Shipit.github_organizations` returning more than `[nil]`), the webhook signature is verified using a GitHub App/secret selected by `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, but the handler that decides which `Repository`/`Stack` receives the event reads a separate field, `repository.full_name`, from that same unverified body. Because these two fields are never cross-checked against each other, a sender who legitimately owns the webhook secret for "their" configured organization can forge a payload whose `repository.owner.login` matches their own org (so signature verification passes with their own secret) while `repository.full_name` points at a stack belonging to a different, victim organization/repository configured in the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App config to check the HMAC against like this: [1](#0-0) [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

and [2](#0-1) 

```
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` resolves a distinct `GitHubApp` instance (and thus a distinct `webhook_secret`) per organization key configured under `secrets.github`, as seen in `lib/shipit.rb`: [3](#0-2) 

So the signature check is scoped strictly to whichever organization's secret matches `repository.owner.login`/`organization.login` — a value taken from the request body itself, before the signature has been validated.

Once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same raw `params` to handlers such as `PushHandler`. Every handler resolves the target `Repository`/`Stack` via `Handler#repository_name`, which reads a *different* field of the same payload: [4](#0-3) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`Repository.from_github_repo_name` splits this `owner/name` string and looks the repo up directly: [5](#0-4) 

For `PushHandler`, that resolved stack is then synced from GitHub using attacker-supplied `ref`/`after` values: [6](#0-5) 

**The broken binding, stated as an equality that the code assumes but never enforces:**
`repository.owner.login` (field used to pick the verifying secret) **==** `repository.full_name`'s owner segment (field used to pick the acted-upon repository).

Before the attacker's request: for legitimate GitHub-originated webhooks, GitHub itself guarantees these two fields describe the same repository, so the equality always holds incidentally, not because the code checks it.

After the attacker's request: an attacker who administers organization `attacker-org` in the same multi-tenant Shipit instance (and therefore knows/controls `attacker-org`'s `webhook_secret`, e.g. by owning that org's GitHub App/webhook config) can sign a payload with:
```
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
`verify_signature` computes/validates the HMAC using `attacker-org`'s secret (which the attacker controls) and passes. The dispatched handler then acts on `victim-org/victim-repo`, triggering `sync_github` (and, depending on which event/handler is targeted — `push`, `status`, `pull_request`, `check_suite`, `membership`, etc. — potentially other cross-tenant side effects) against a stack the attacker's organization was never authorized to touch.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. In a Shipit deployment configured for multiple GitHub organizations (a supported, documented mode per `Shipit.github_organizations`/`github_app_config`), any tenant with a valid webhook secret for their own org can forge events attributed to (and processed against) a completely different tenant's repository/stack, without ever needing that victim's webhook secret, GitHub App key, or repository access. Depending on the handler reached, this can drive unwanted `GithubSyncJob` executions, spurious commit statuses, membership/team mutations, or merge-queue/pull-request state changes on a repository the attacker does not own — a cross-repository/cross-tenant write performed under a forged identity, satisfying the "cross-repository writes" Critical impact criterion.

### Likelihood Explanation
Requires: (a) the Shipit instance to be configured in multi-organization mode with more than one entry in `secrets.github` (a supported, non-default but documented configuration), and (b) the attacker to control (or be a legitimate webhook sender for) at least one of the configured organizations. Given those preconditions — which involve no privileged Shipit account, no `ApiClient` token, and no access to the victim organization's secret — the forgery itself is a single crafted HTTP POST with a correctly computed HMAC using the attacker's own known secret. No rate limiting or timing constraints apply.

### Recommendation
Bind the field used for signature-secret selection to the field used for repository resolution: after computing `repository_owner`, verify that it equals the owner segment of `payload.dig('repository', 'full_name')` (case-insensitively) before proceeding, and reject the request (422) on mismatch. Alternatively, verify the signature using the config resolved from the same value (`full_name`'s owner) used later by `Handler#repository_name`/`Repository.from_github_repo_name`, so a single field of the payload is authoritative for both authentication and dispatch.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-org mode, per `Shipit.github_organizations`).
2. Attacker (who administers `attacker-org` and knows its `webhook_secret`) sends `POST /webhooks` with `X-Github-Event: push` and a JSON body:
   ```json
   {
     "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"},
     "ref": "refs/heads/master",
     "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
   }
   ```
   with `X-Hub-Signature` computed as `sha1=HMAC(attacker-org secret, raw_body)`.
3. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `Shipit.github(organization: "attacker-org")` and validates successfully because the attacker used the correct secret for that org.
4. `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack — a write triggered under a forged, unauthorized cross-organization signature.

**Uncertainty noted:** I could not fully trace every downstream handler (`check_suite`, `membership`, `status`, `pull_request` handlers) to enumerate the complete set of side effects reachable this way within the tool budget available; the `PushHandler` path is confirmed directly from the code shown above. Whether this is exploitable in a given deployment also depends on that deployment actually running in multi-organization mode, which I could not confirm from the code alone (it is a supported code path, not verified as universally enabled).

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
