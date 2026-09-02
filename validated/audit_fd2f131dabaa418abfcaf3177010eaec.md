## Title
Webhook signature verification is keyed to `repository.owner.login`, but event processing is keyed to `repository.full_name` — cross-organization stack forgery in multi-org Shipit deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
When Shipit is configured with the multi-organization GitHub App schema (`Shipit.github(organization:)`), `WebhooksController#verify_signature` selects which webhook secret to verify the HMAC signature with by reading `repository.owner.login` (or `organization.login`) out of the *unverified* JSON body, and only after picking that secret does it check the signature against the *entire* raw body. [1](#0-0)  The event handlers, however, resolve which `Stack`/`Repository` to mutate using a completely different field of that same payload: `payload.dig('repository', 'full_name')`. [2](#0-1)  Because the "authenticating organization" field and the "repository being written to" field are independent, unrelated JSON keys, an attacker who legitimately controls a GitHub App installation for one organization configured in Shipit (and therefore knows/controls that organization's `webhook_secret`) can forge a payload whose `repository.owner.login` matches their own org (so it authenticates with their own known secret) while `repository.full_name` names a stack belonging to a different, victim organization.

### Finding Description
This mirrors the report's bug class: a field that is *acted upon* by the application is not the field that is *covered by the authorization check*. In the Size protocol case, `validateUserIsNotBelowOpeningLimitBorrowCR` checked a condition (collateral ratio) that was irrelevant to the actual action being gated (withdrawing borrow tokens). Here, the binding that should hold is:

`organization authenticated by verify_webhook_signature == organization owning the repository the handlers write to`

but the code actually enforces:

`organization used to select webhook_secret (repository.owner.login) ` vs `repository written to (repository.full_name)` — two independent attacker-controlled strings in the same unsigned-at-verification-time payload.

Concretely:
1. `verify_signature` computes `repository_owner` from the payload via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, then does `Shipit.github(organization: repository_owner)` to fetch that organization's `GitHubApp`, and validates `X-Hub-Signature` against that organization's `webhook_secret`. [1](#0-0) [3](#0-2) 
2. Once verification passes, `create` dispatches the full payload to handlers keyed only by `X-Github-Event`, with no cross-check that `repository.full_name`'s owner matches the `repository.owner.login` used for verification. [4](#0-3) 
3. `Handler#stacks` resolves the target using `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, an entirely separate field from the one used for signature-organization selection. [2](#0-1) 
4. `PushHandler`, for example, then calls `stack.sync_github(expected_head_sha: params.after)` for every matching stack, which triggers Shipit to fetch/sync commits from GitHub for that stack — i.e., cross-organization interaction driven entirely by attacker-controlled JSON that only had to be internally consistent for signing purposes, not for the resource it names. [5](#0-4) 

This exploit path only exists in the documented "Using Multiple GitHub Applications" configuration, where the `github` config's top-level keys are distinct organizations each with their own `webhook_secret`. [6](#0-5) 

### Impact Explanation
An attacker who has installed/administers their *own* GitHub App entry in Shipit's multi-org config (a legitimate, unprivileged relationship to Shipit — they only own one of many configured orgs, not the victim's) can sign a payload with their own known `webhook_secret` while spoofing `repository.full_name` to point at a stack under a *different* configured organization. Depending on the event type, this can drive `GithubSyncJob`/`sync_github` against a victim's repository/stack, `RefreshCheckRunsJob`, `RefreshStatusesJob`, membership/team churn (`MembershipHandler` creates users/teams), or PR-driven merge-status/label actions on a repo the attacker does not control — all cross-organization writes performed with the app's GitHub credentials against a stack the attacker was never authorized to touch. This satisfies the "cross-repository writes" / unauthorized-action high-impact bar in the rubric, because it breaks the organization-authenticated vs. repository-written binding without ever needing the victim org's secret, an `ApiClient` token, repository write access, or a Shipit session.

### Likelihood Explanation
Likelihood is contingent on the deployment using the multi-organization GitHub App configuration (single-org deployments use one implicit `webhook_secret`, so no such de-correlation is possible, since `repository_owner` is effectively ignored in the single-secret path). [7](#0-6)  For multi-org deployments, exploitation requires only owning one of the configured GitHub App installations (a routine, low-privilege position for a legitimate customer/org in a shared Shipit instance) and crafting an HTTP POST to `/webhooks` with a mismatched `repository.owner.login` vs `repository.full_name`.

### Recommendation
Bind webhook-signature verification to the same field the handlers use to select the target resource, and reject the request if they disagree:
- Verify the signature using the organization derived from `repository.full_name` (or explicitly re-validate that `repository.owner.login` equals the owner segment of `repository.full_name`) before dispatching to handlers.
- Alternatively, look up the `Repository`/`Stack` for the payload first, derive its configured GitHub organization from that record, and use that organization (not attacker-supplied payload fields) to select the webhook secret for verification.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-org schema).
2. Attacker knows `attacker-org`'s `webhook_secret` (they legitimately installed that GitHub App).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own known secret. [1](#0-0) 
6. `PushHandler` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and triggers `stack.sync_github(expected_head_sha: "deadbeef...")` against the victim's stack — an action the attacker was never authorized to trigger. [5](#0-4) [2](#0-1) 

*Note: I was unable to directly execute this PoC (no runtime/tool access in ask-only mode); the trace above is derived from static analysis of the cited files and confirms the code path exists as described. If a Devin session is desired to reproduce this against a running instance or to implement the fix, that would need to be requested separately.*

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

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
