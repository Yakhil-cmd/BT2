### Title
Webhook signature verification authenticates by `repository.owner.login`/`organization.login` while all event handlers act on the independent `repository.full_name` field, allowing cross-organization writes — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC `webhook_secret`) used to validate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`), but every downstream event handler resolves the target `Repository`/`Stack` using the independent `repository.full_name` field of the same JSON body. Because these are two separate, attacker-suppliable fields inside one signed blob, an org boundary is authenticated on one field while state mutations are keyed on a different field, letting a webhook that is validly signed for organization A masquerade as an event for organization B's repository.

### Finding Description
`verify_signature` computes the signing organization like this: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, and it drives which `GitHubApp` config (and therefore which `webhook_secret`) is used in `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, per `Shipit.github`/`Shipit.github_app_config` (`lib/shipit.rb`), which is only meaningful when Shipit is configured with the multi-organization schema shown in `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`.

Once the HMAC check passes, the raw JSON is dispatched to handlers (`app/controllers/shipit/webhooks_controller.rb` `create`), and those handlers derive the *target* repository from a completely different key, `repository.full_name`, e.g.: [3](#0-2) 

Nothing cross-checks that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` value that selected the signing secret. Both fields live in the same attacker-crafted JSON body and are only integrity-protected as a whole by the signature of *whichever* organization's secret is chosen based on `repository.owner.login`. This means: if an attacker legitimately controls a GitHub App installation for Organization A registered in Shipit (a normal, unprivileged self-service scenario when Shipit hosts multiple orgs, per `docs/setup.md` "Using Multiple Github Applications"), they can trigger/craft a webhook where `repository.owner.login = "OrgA"` (so the correct, known `webhook_secret` for OrgA computes a valid signature) but `repository.full_name = "OrgB/some-repo"`. The signature check passes using OrgA's secret, yet the handler acts on OrgB's `Repository`/`Stack`.

Test fixtures confirm `full_name` is treated as an independently mutable field distinct from `owner.login`, and is exactly what handlers key off of: [4](#0-3) 

The binding broken is: *the organization that authenticated the webhook (`repository.owner.login`/`organization.login`, used to pick the `webhook_secret`) vs. the repository that is actually written (`repository.full_name`, used by every handler to find the `Repository`/`Stack`)*. These are supposed to be the same GitHub-issued object, but the code never enforces that equality — it trusts them independently.

### Impact Explanation
This breaks the trust boundary between organizations onboarded to a shared, multi-org Shipit deployment. A party who legitimately controls the GitHub App/webhook configuration for one organization (Org A) can forge webhook deliveries that are cryptographically valid (signed with Org A's own secret) but whose payload content targets a repository belonging to a different organization (Org B) hosted on the same Shipit instance. Depending on the event type this enables cross-repository state changes such as creating/archiving review stacks, updating pull request state associations, or triggering `GithubSyncJob` for Org B's stacks (`app/models/shipit/webhooks/handlers/push_handler.rb`) — effectively an unauthorized write into another organization's deployment pipeline that Org A has no legitimate access to. This matches the "cross-repository writes" Critical impact category.

### Likelihood Explanation
Requires: (1) Shipit configured for multiple GitHub organizations (a documented, supported configuration), and (2) attacker control of a valid webhook secret for at least one onboarded organization — which is a normal, unprivileged capability for anyone who can install/administer the Shipit GitHub App for their own organization, not a compromise of Shipit's own secrets. No access to Org B, no `ApiClient` token, and no privileged Shipit account is required. The likelihood is moderate to high in any multi-tenant/multi-org Shipit deployment.

### Recommendation
After signature verification selects the authenticating organization, all handlers must re-derive the target `Repository`/`Stack` strictly from that authenticated organization (e.g., re-check that the owner segment of `repository.full_name` equals the verified `repository_owner`/`organization.login`), rejecting the webhook (422) on mismatch, rather than trusting `repository.full_name` independently in each handler.

### Proof of Concept
1. Shipit is configured with the multi-org schema (`OrgA`, `OrgB`) as in `docs/setup.md`/`test/dummy/config/secrets_double_github_app.yml`, each with its own `webhook_secret`.
2. Attacker administers OrgA's GitHub App installation and therefore knows/controls OrgA's `webhook_secret`.
3. Attacker crafts a `push` (or `pull_request`) JSON body where `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/target-repo"`, and other required fields per handler's `params do ... end` schema.
4. Attacker computes `X-Hub-Signature` using OrgA's `webhook_secret` over the raw body and POSTs to `/github/webhooks`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")` and the signature validates successfully.
6. The dispatched handler (e.g. `PushHandler`/`EditedHandler`) resolves the target via `repository.full_name`, acting on `OrgB/target-repo`'s `Stack`/`PullRequest` records, even though the request was never authenticated by OrgB.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end
```
