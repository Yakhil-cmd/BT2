### Title
Webhook organization/secret selection is bound to `repository.owner.login`, while the acted-upon repository is resolved from the unrelated `repository.full_name` field, allowing one tenant's GitHub App to forge webhook events for another tenant's repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
When Shipit is configured with the documented "Using Multiple Github Applications" scheme, each GitHub organization gets its own `app_id`/`installation_id`/`webhook_secret` under `secrets.github.<org>` <cite repo="Camomtat/shipit-engine--021" path="docs/setup.md" start="182="209 /> [1](#0-0) . `Shipit.github(organization:)` looks up the per-organization config keyed by the organization name to build the `GitHubApp` used for signature verification [2](#0-1) .

`WebhooksController#verify_signature` selects *which* organization's `webhook_secret` to verify the incoming signature against using `repository_owner`, which is read from the JSON body field `repository.owner.login` (or `organization.login`): [3](#0-2) [4](#0-3) 

However, once signature verification passes, `Shipit::Webhooks::Handlers::Handler` (the base class used by every push/status/pull_request/membership handler) resolves the actual `Repository`/`Stack` that the event acts on using a **different** JSON field, `repository.full_name`: [5](#0-4) 

`repository.owner.login` and `repository.full_name` are two independent, attacker-controlled strings inside the same unsigned-until-verified JSON payload. Nothing ties them together: the signature only proves the payload was signed with the secret belonging to whatever organization `repository.owner.login` claims, but the code that actually performs the mutation (syncing branches, recording statuses, closing/merging pull requests, creating review stacks, etc.) trusts `repository.full_name` instead.

This breaks the intended trust binding: `organization authenticated == repository written`. An attacker who legitimately controls (or has compromised) the GitHub App installation/webhook secret for Organization A (a real, valid tenant on the same shared Shipit instance) can craft a payload where:
- `repository.owner.login = "OrgA"` (so `verify_signature` fetches OrgA's `webhook_secret` and the HMAC validates), and
- `repository.full_name = "OrgB/some-private-repo"` (so the handler acts on Organization B's stack).

The webhook is accepted (`verified == true`) and dispatched to handlers, which then act on OrgB's `Stack`/`Repository`/`PullRequest`/`Commit` records as if the event legitimately came from GitHub for OrgB.

### Impact Explanation
Depending on which webhook event/handler is exercised, this can escalate to a genuine cross-organization write on GitHub performed with Shipit's own OrgB credentials, not the attacker's:
- Forging a `status` event lets the attacker write fabricated CI status (`success`) for arbitrary commit SHAs on OrgB's stacks, influencing Shipit's deploy-gating logic for a repository the attacker has no access to.
- Forging `pull_request`/`merge_status` related events (open/label/merge-queue related handlers) can move an OrgB pull request through Shipit's merge queue, which later calls `stack.github_api` (OrgB's own installation token) to actually merge/close the PR on GitHub - an unauthorized cross-repository/cross-organization merge triggered purely from a payload signed with OrgA's secret.
- Forging `push` events can trigger `sync_github` on OrgB stacks.

This satisfies the "cross-repository writes" / "unauthorized deploy, rollback, or merge" Critical impact criteria, because the write ultimately executes with the victim organization's GitHub credentials while authorization was only ever established for the attacker's own organization.

### Likelihood Explanation
This requires the host application to be configured with the multi-organization GitHub App scheme (a documented, supported configuration) and requires the attacker to control a legitimate GitHub App installation/webhook secret for at least one of the configured organizations sharing the Shipit instance - i.e., be a normal, unprivileged tenant with respect to the victim organization. No Shipit session, `ApiClient` token, or GitHub write access to the victim repository is required; only the ability to produce one validly-signed webhook delivery for the attacker's own organization, which any real GitHub App installation naturally provides (e.g., by pushing a commit or opening a PR in their own repository) or by directly replaying/crafting an HMAC-signed request offline once they know their own secret.

### Recommendation
Bind `repository_owner` used for secret selection to the exact same value used by `Shipit::Webhooks::Handlers::Handler#repository_name` (or vice versa), and additionally verify, after signature validation, that the owner segment of `repository.full_name` matches the organization whose secret validated the signature. Reject the webhook (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org example).
2. As the legitimate GitHub App/webhook sender for `OrgA`, compute a valid `X-Hub-Signature` (`sha1=HMAC(OrgA_webhook_secret, body)`) over a JSON body such as:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha in OrgB repo>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. POST this to `/webhooks` with `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `WebhooksController#verify_signature` selects `Shipit.github(organization: "OrgA")` (from `repository_owner`), verifies the signature successfully against `OrgA`'s secret [3](#0-2) .
5. `PushHandler#process` (inherited `stacks` from `Handler`) resolves `Repository.from_github_repo_name("OrgB/victim-repo")` via `repository_name = payload.dig('repository', 'full_name')` [5](#0-4)  and triggers `sync_github` on `OrgB`'s stack — despite the request never being signed by `OrgB`'s secret.

### Citations

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
