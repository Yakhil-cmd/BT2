### Title
Webhook signature verification binds trust to `repository.owner.login`/`organization.login`, but webhook handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using `repository.owner.login` (falling back to `organization.login`), while the handlers that decide *which repository/stack is actually mutated* use a completely different field, `repository.full_name`. Because both fields live in the same attacker-supplied JSON body, an attacker who controls a legitimate GitHub App installation on their own organization (and therefore knows that organization's `webhook_secret`) can forge a webhook body whose `repository.owner.login` matches their own org (so the correct, known secret is selected and the HMAC verifies), while `repository.full_name` is set to a victim repository belonging to a completely different organization. The handler layer never re-checks that the two fields agree, so the victim's stack is acted upon under signature "authentication" that was never issued by the victim's organization.

### Finding Description
`verify_signature` computes the authenticating organization as: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

and: [2](#0-1) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: ...)` resolves to a per-organization `GithubApp` configuration/secret (raising `Shipit::GithubOrganizationUnknown` for unregistered orgs), confirming Shipit is designed to support multiple, independently-secreted GitHub App installations in the same deployment.

Once the signature check passes, `WebhooksController#create` dispatches the raw JSON to the registered handler(s) for the event, unmodified: [3](#0-2) 

Every handler resolves the target repository/stack via the base `Handler` class using an entirely different field, `repository.full_name`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler`, for example, uses these `stacks` to trigger a live sync against GitHub for whatever branch/stack matches, using attacker-supplied `after` sha: [5](#0-4) 

```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
```

Nothing ties `repository.owner.login` (used to pick the verifying secret) to `repository.full_name` (used to pick the acted-upon repository/stack). The HMAC only proves the raw body was signed with *some* known secret — it says nothing about which organization's data is inside that body. An attacker who owns/administers their own Shipit-integrated GitHub organization ("attacker-org") knows their own org's `webhook_secret` (it is configured by them when they install the GitHub App for their org, as documented in `docs/setup.md`). They can build any payload they like — including one whose `repository.full_name` names `victim-org/victim-repo` — set `repository.owner.login` to `attacker-org`, sign the whole raw body themselves with their own known secret, and POST it to `/webhooks`. `verify_signature` looks up `attacker-org`'s app, verifies successfully (because the attacker legitimately possesses that secret), and the request proceeds to handlers that read and act on `repository.full_name` = the victim's repo, with zero involvement of the victim's actual GitHub App/secret.

This is the structural analog of H-5: the value that is checked/authenticated (`repository.owner.login` → org secret) is not the same value that is subsequently used to select what gets written/mutated (`repository.full_name` → target `Repository`/`Stack`), even though both live inside the one payload that was nominally "verified." Just as the Solidity bug let a `_part1`/`_part2` mismatch silently corrupt the key actually deposited, here a `repository.owner.login`/`repository.full_name` mismatch silently misdirects a "verified" webhook onto an unrelated repository.

### Impact Explanation
Any tenant that legitimately installs the Shipit GitHub App on their own organization (a normal, unprivileged onboarding action, not requiring any Shipit session/API token/admin access) can forge webhook events that Shipit will treat as verified GitHub events for **any other repository already tracked by that Shipit instance**, because the org whose secret authenticated the request is never checked against the repository the handlers actually mutate. Concretely, for the `push` event this lets an attacker force `Stack#sync_github` to run for a victim stack with an attacker-chosen `expected_head_sha`, and for the `status`/`check_suite` events (which follow the same `repository.full_name`-driven `stacks` resolution inherited from `Handler`) this lets the attacker inject fabricated commit statuses/check-suite results for a victim's commits. Because Shipit gates deploys on required/blocking commit statuses, an attacker able to forge a passing status for a victim repository can help satisfy the conditions for an **unauthorized deploy** of a specific commit in a repository the attacker does not control — a cross-repository/cross-organization trust break with no legitimate credential to the victim organization involved.

### Likelihood Explanation
Likelihood is high in any Shipit deployment that services more than one GitHub organization (a supported and documented configuration, given `Shipit.github(organization:)` and per-org `webhook_secret`). The only prerequisite is that the attacker be a legitimate, unprivileged administrator of their own separate organization/App installation on that same Shipit instance — no access to the victim's secret, session, or API token is required, satisfying the "unprivileged attacker" constraint.

### Recommendation
Bind webhook signature verification and payload interpretation to the same field. Concretely: after selecting `github_app` via `repository_owner`, re-derive the acted-upon repository strictly from that same organization (e.g. require `params.dig('repository', 'full_name')&.split('/', 2)&.first == repository_owner`, or better, always resolve `repository_owner` from `repository.full_name`'s owner segment rather than a separately-controllable `repository.owner.login`/`organization.login` field), and reject the webhook (422) if they disagree.

### Proof of Concept
1. Attacker legitimately installs the Shipit GitHub App on `attacker-org` and knows/derives `attacker-org`'s `webhook_secret` from their own App settings.
2. Attacker constructs a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "Shopify/shipit-engine"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org's webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `attacker-org`'s `GithubApp`, and `verify_webhook_signature` succeeds because the attacker legitimately holds that secret [1](#0-0) .
5. `create` dispatches to `PushHandler`, whose `stacks` resolves via `payload.dig('repository', 'full_name')` = `"Shopify/shipit-engine"` [4](#0-3) , and `sync_github(expected_head_sha: params.after)` is invoked against the victim's `master` stack [5](#0-4)  — despite the request never having been signed by `Shopify`'s own webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
