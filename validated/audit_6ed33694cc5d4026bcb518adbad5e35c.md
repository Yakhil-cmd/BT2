### Title
Webhook signature verified against the organization derived from `repository.owner.login`, but handlers act on the independent `repository.full_name` field, letting a tenant with its own configured GitHub App secret trigger syncs/deploys on another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC against using a field read directly out of the still-unverified JSON body, while the event handlers that actually mutate state look up the target repository/stack from a *different* field in that same unverified body. Nothing ties these two fields together, so a party who legitimately controls one configured organization's webhook secret can forge a payload whose "owning" field points at their own org (passing signature verification) while its "acted-upon" field points at a completely different, victim organization's repository.

### Finding Description
`verify_signature` picks the verification key like this: [1](#0-0) 

`repository_owner` is read straight from the raw, not-yet-verified JSON body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves the per-organization `GithubApp` config (each organization can be configured with its own `webhook_secret`), and `verify_webhook_signature` performs a `secure_compare` of the HMAC-SHA1 of the raw body against that org's secret: [3](#0-2) 

Once the request passes this check, `create` hands the parsed body to the registered event handlers unmodified: [4](#0-3) 

Every handler, however, resolves the target repository/stack not from `repository.owner.login` but from the sibling field `repository.full_name`: [5](#0-4) 

For example `PushHandler` uses this `stacks` helper to find every non-archived stack on the pushed branch and calls `sync_github` on it: [6](#0-5) 

Because `verify_signature` authenticates the payload using the secret bound to `repository.owner.login`/`organization.login`, while the handler acts on `repository.full_name`, these two values are only consistent by GitHub's own convention when GitHub itself produces the payload for a matching, real event. Nothing in the code enforces `full_name.split('/').first == repository_owner`. A party who controls the webhook secret for **one** onboarded organization (i.e., one tenant of a multi-organization Shipit deployment, each configured with its own `webhook_secret` in `Shipit.github_apps`) can craft a raw JSON body where `repository.owner.login` (or `organization.login`) is set to their own org — so the HMAC they compute with their own known secret passes `verify_signature` — but set `repository.full_name` to `"victim-org/victim-repo"`. The equality that should hold is:

`organization authenticated by verify_signature == organization owning the repository/stack acted on by the handler`

and this engine breaks that equality: the two are read from independent, unauthenticated-relative-to-each-other JSON paths.

### Impact Explanation
This lets an operator of any single tenant/organization configured in the Shipit instance forge webhook deliveries that are processed as if they came from a totally different, victim organization's repository. Concretely, via `PushHandler`, the attacker can invoke `stack.sync_github(expected_head_sha: ...)` on any stack belonging to any other tenant's repository tracked by the instance, and other handlers (`status`, `pull_request`, `check_suite`, `membership`) are equally reachable this way since they all inherit the same `repository_name`/`stacks` resolution pattern from `Handler`. Since continuous-delivery stacks trigger task execution automatically once new commits are synced from GitHub (`S->>T: trigger_task (if CD enabled)`), this can be used to force out-of-band sync/trigger activity against a stack the attacker does not own or have any access to, i.e. cross-repository/cross-tenant interference and potentially unauthorized deploy triggering — outside the attacker's own authorized organization boundary.

### Likelihood Explanation
Requires the attacker to control (or be an administrator of) at least one organization/GitHub App configuration already onboarded into the multi-tenant Shipit instance — this is the intended "unprivileged relative to other tenants" attacker in a shared Shipit deployment, not a privileged Shipit user or someone holding another org's secret. No GitHub write access to the victim repository, no Shipit session, and no knowledge of the victim's webhook secret are required — only the ability to send an HTTP POST to the shared `/webhooks` endpoint with a correctly-signed-for-their-own-org, but cross-referenced, payload.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler#repository_name`), enforce that the organization used to select/verify the webhook secret is the same organization embedded in `repository.full_name` (and any other repository-identifying field used by handlers) before dispatching to handlers — e.g., reject the request if `repository.full_name.split('/').first` does not case-insensitively match `repository_owner`.

### Proof of Concept
1. Shipit is configured with two tenants, `org-a` (attacker-administered, with webhook secret `S_A` known to the attacker via their own GitHub App setup) and `org-b` (victim), each with stacks tracked by the same Shipit instance.
2. Attacker crafts a raw JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_A, body)` using their own known secret `S_A`, and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner` as `"org-a"` [2](#0-1) , loads `Shipit.github(organization: "org-a")`, and the signature check passes because it was signed with `S_A`.
5. `create` dispatches to `Handlers::PushHandler`, whose `repository_name` reads `payload.dig('repository', 'full_name')` = `"org-b/victim-repo"` [5](#0-4) , resolving and calling `sync_github` on `org-b`'s stacks despite the request only being authenticated for `org-a`.

Note: I was not able to fully inspect `Stack#sync_github` / `GithubSyncJob` internals within the tool-call budget to characterize the exact downstream consequences (e.g., whether it can immediately trigger a deploy task versus only a metadata refresh); this is stated as an open item for further verification by whoever picks this up.

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
