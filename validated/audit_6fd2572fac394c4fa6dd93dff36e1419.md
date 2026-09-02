### Title
Webhook signature verified against `repository.owner.login`'s org, but the acted-upon `Stack` is selected via unbound `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/organization whose `webhook_secret` is used to validate the HMAC signature based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body. Once the signature is validated, the full payload is forwarded to event handlers that determine which `Stack`/`Repository` to act on using a *different* field of the same unverified payload: `repository.full_name`. An attacker who legitimately controls a GitHub App/repository in OrgA (and therefore knows OrgA's `webhook_secret`, e.g. from their own webhook settings page) can sign a payload where `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/some-repo"`, passing signature verification against OrgA's secret while the handler acts on an OrgB stack the attacker has no access to.

### Finding Description
`verify_signature` computes the org used for HMAC verification purely from body fields: [1](#0-0) [2](#0-1) 

The signature check (`verify_webhook_signature`) only validates that the raw body is HMAC-signed with **that** org's secret — it says nothing about which repository the payload claims to describe: [3](#0-2) 

After verification succeeds, `create` re-parses the same raw body and dispatches it, unmodified, to all registered handlers for the event: [4](#0-3) 

Handlers resolve the target `Stack` using a completely different field of the body — `repository.full_name` — not `repository.owner.login`: [5](#0-4) [6](#0-5) 

`PushHandler`, for example, triggers a full GitHub sync (and potentially a deploy if continuous deployment is enabled) for whatever stack `Repository.from_github_repo_name` resolves to: [7](#0-6) 

`CheckSuiteHandler` similarly acts on stacks resolved the same way: [8](#0-7) 

The binding that should hold is: `organization authenticated by signature == organization of the repository actually acted upon`. Because both values are taken from attacker-controlled JSON, and only one of them (`repository.owner.login`) feeds the signature check while the other (`repository.full_name`) feeds the actual authorization-sensitive lookup, that equality is never enforced. An attacker who knows the `webhook_secret` for *any* single organization configured in this Shipit instance (e.g. because they administer that GitHub App/organization themselves) can forge a signature that is valid for that organization while making the payload describe a repository belonging to a completely different organization, causing Shipit to sync/deploy that other organization's stack.

### Impact Explanation
This breaks the cross-organization/cross-repository isolation the webhook endpoint is supposed to provide: signature validity for OrgA does not imply the payload's target repository is OrgA's. `GithubSyncJob` (triggered via `PushHandler`) fetches new commits from GitHub for the *target* stack using the stack's own legitimate credentials and, if `continuous_deployment` is enabled on that stack, can result in an unsolicited deploy being kicked off for OrgB's stack purely from a request forged and signed by someone who only controls OrgA. This is a cross-organization write/trigger — an unauthorized deploy — falling squarely within the allowed "unauthorized deploy" impact category, even though the attacker never possessed OrgB's credentials.

### Likelihood Explanation
Exploitability requires only that the attacker administers (or has webhook access to) any single GitHub organization/App configured on the Shipit instance — a routine, low-privilege scenario in any multi-tenant Shipit deployment serving several organizations, and does not require possessing a Shipit session, `ApiClient` token, or another organization's secret. Because `repository_owner` and `repository_name` are derived from two independent JSON fields with no cross-check, constructing the divergent payload is trivial (plain JSON body edit) and the HMAC signature computation is exactly the documented GitHub Apps mechanism, so likelihood is moderate-to-high in any installation with more than one configured organization.

### Recommendation
Enforce that the organization used to validate the webhook signature is the same organization that owns the repository referenced by `repository.full_name` before dispatching to handlers — e.g., verify `repository.owner.login`/`organization.login` equals the owner segment of `repository.full_name`, and reject the request (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` first, verify the signature using that repository's actual owning organization's secret, and only then process the event.

### Proof of Concept
1. Attacker legitimately administers `OrgA`'s GitHub App on this Shipit instance and therefore knows `OrgA`'s `webhook_secret`.
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<some existing sha in OrgB's repo>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs to `Shipit::WebhooksController#create` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and validates the signature successfully (attacker knows this secret). [1](#0-0) 
5. `create` dispatches the same payload to `PushHandler`, whose `repository_name` resolves to `"OrgB/target-repo"` via `payload.dig('repository', 'full_name')`, looking up and syncing/deploying `OrgB`'s stack. [5](#0-4) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
