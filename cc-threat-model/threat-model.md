# Threat model — Discourse (github.com/cx-benchmark/discourse)

## system

**Purpose.** Discourse is a self-hostable community forum (README.md). The back end is "a Rails app. It responds to requests RESTfully in JSON"; the front end is an Ember.js single-page app; PostgreSQL is the main store and Redis is used "as a cache and for transient data" (README.md "Built With"). One process can serve many forums ("sites") through RailsMultisite (`config/initializers/200-first_middlewares.rb`, `config/multisite.yml.production-sample`).

**Main components (read unless marked)**
- **Rack/Rails entry:** `config.ru` → `Discourse::Application` (`config/application.rb`).
  - Front of the stack (`200-first_middlewares.rb`): RailsMultisite::Middleware (multisite only), ProcessingRequest, OverloadProtections, RequestTracker (per-IP limits; `ActionDispatch::RemoteIp` is moved in front of it), MessageBus.
  - Later in the stack: Discourse::Cors (`008-rack-cors.rb`); EnforceHostname (`lib/middleware/enforce_hostname.rb`; not added in development or with SKIP_ENFORCE_HOSTNAME=1); DefaultHeaders; ContentSecurityPolicy::Middleware; CspScriptNonceInjector; AnonymousCache (`099-anon-cache.rb`).
- **Controllers:** 96 in `app/controllers/*.rb`, plus `users/`, `json_api_kit/` and `api/groups_controller.rb` (`/api/groups/:id`, `ensure_admin`). `app/controllers/admin/` holds 56 files: 40 inherit `Admin::AdminController` (`requires_login` + `ensure_admin`), 14 inherit `Admin::StaffController` (`ensure_staff`), and the other 2 are those base classes.
- **Authorization:**
  - `Guardian` (`lib/guardian.rb`, `lib/guardian/*.rb`). Plugins extend it with `add_to_class(:guardian, …)` or `guardian_extensions.rb`.
  - Route constraints `AdminConstraint`, `StaffConstraint` and `ImpersonatorConstraint` (`lib/*_constraint.rb`).
  - A generic ACL (`lib/acl/`, `app/models/access_control_list.rb`), used by the boards plugin.
- **Authentication:**
  - `lib/auth/default_current_user_provider.rb` and `app/controllers/session_controller.rb`.
  - OmniAuth: `config/initializers/009-omniauth.rb`, `lib/auth/*_authenticator.rb`, auth plugins.
  - DiscourseConnect consumer and provider: `lib/discourse_connect_base.rb`, `app/models/discourse_connect.rb`, `lib/discourse_connect_provider.rb`.
  - WebAuthn and passkeys: `lib/discourse_webauthn/` (out of view).
  - MCP OAuth authorization server: `lib/discourse_mcp/`, `app/controllers/mcp*_controller.rb`.
- **Content pipeline:**
  - `PrettyText.markdown` (`lib/pretty_text.rb`) runs the client's markdown-it engine (`frontend/discourse-markdown-it`) and the xss.js allowlist sanitizer (`frontend/pretty-text/addon/sanitizer.js`) inside a MiniRacer V8 context.
  - `PrettyText.cleanup` then applies Nokogiri/Loofah passes; `lib/cooked_post_processor.rb` post-processes cooked HTML.
  - Oneboxes: `lib/oneboxer.rb`, `lib/onebox/`, with the Sanitize gem config in `lib/onebox/sanitize_config.rb`.
- **Outbound HTTP:** `FinalDestination` (`lib/final_destination.rb`, `lib/final_destination/{http,ssrf_detector,faraday_adapter,resolver,connector}.rb`).
- **Uploads and images:**
  - `app/controllers/uploads_controller.rb`, `lib/upload_creator.rb`, `lib/file_store/` (local or S3).
  - ImageMagick runs under `config/imagemagick/policy.xml`.
  - libvips runs in a separate sandboxed worker process (`lib/discourse_vips/`, `script/discourse_vips_worker`).
- **Email:**
  - Inbound parsing in `lib/email/receiver.rb`. Mail arrives via `POST /admin/email/handle_mail` (API key), POP3 (`app/jobs/scheduled/poll_mailbox.rb`, out of view) or group IMAP (out of view).
  - Bounce webhooks: `app/controllers/webhooks_controller.rb`.
- **Real time:** MessageBus (`config/initializers/004-message_bus.rb`), presence (`app/controllers/presence_controller.rb`).
- **Background jobs:** Sidekiq (`app/jobs/`, `config/sidekiq.yml`).
- **Bundled plugins** (`plugins/`, 46). Each is gated by an `enabled_site_setting` whose default is in its `config/settings.yml`.
  - On by default: chat, checklist, details, lazy-videos, local-dates, narrative-bot, presence, reactions, solved, templates, topic-voting, footnote, poll, spoiler-alert.
  - Off by default, among others: discourse-ai, data-explorer, automation, workflows, chat-integration, assign, events, live, boards, subscriptions, patreon, zendesk, github, styleguide, and the auth plugins (apple, amazon, microsoft, oauth2-basic, openid-connect, lti).
- **Frontend:** `frontend/discourse` (Ember, Glimmer `.gjs` templates; admin UI in `frontend/discourse/admin`). System themes are in `themes/`. Admin-installed theme JS is transpiled server-side in V8 (`lib/asset_processor.rb`, `lib/theme_javascript_compiler.rb`).

**Principals the code trusts**
- **The operator.** GlobalSettings come from `config/discourse.conf` or `DISCOURSE_*` env vars (`app/models/global_setting.rb` FileProvider/EnvProvider). Postgres and Redis are trusted stores: Redis holds the fallback `secret_key_base` (`GlobalSetting.safe_secret_key_base`), server sessions, rate-limit counters and a Marshal-serialized cache (`lib/cache.rb`).
- **Developers.** `developer_emails` (`config/environments/production.rb`) feeds `Guardian#is_developer?`, which allows impersonating admins and the mini profiler. `make_developer_admin` (`default_current_user_provider.rb`) grants admin on login to those emails.
- **Roles:** admins, moderators (together, staff), category-group moderators (`enable_category_group_moderation`, default false), trust levels TL0–TL4, staged users (created from inbound email), anonymous.
- **Plugin code:** Ruby loaded at boot with full process privilege (`Discourse.activate_plugins!` in `config/application.rb`). The admin UI only lists plugins and their settings (`Admin::PluginsController#index/show`).
- **Theme code:** admin-installed JS and CSS, served to every user who gets that theme.

**Build, ship, deploy (per its own files)**
- `docs/INSTALL.md`: "The only officially supported installs of Discourse are Docker based", using discourse_docker (out of view).
- nginx sits in front (`config/nginx.sample.conf`; sets `X-Forwarded-For $remote_addr`, X-Accel-Redirect for `/uploads/`). App servers are pitchfork or unicorn (`config/pitchfork.conf.rb`, `config/unicorn_launcher`).
- `config/environments/production.rb`: eager load, X-Accel-Redirect, Rails static file serving only when `serve_static_assets` is set (default false, `config/discourse_defaults.conf`).
- **Prebuilt front-end assets:**
  - `script/assemble_ember_build.rb` (run from `lib/tasks/assets.rake`) curls `https://get.discourse.org/discourse-assets/<version>-<sha8>/<env>.tar.gz` and extracts it into `frontend/discourse/dist` and `app/assets/generated`.
  - It skips the download if `DISCOURSE_DOWNLOAD_PRE_BUILT_ASSETS=0` or if the JS sources have local changes.
  - `download_prebuild_assets!` does not check a checksum or signature.
  - The bundles come from `.github/workflows/publish-assets.yml` (on push to main and release/*). It runs `script/publish_built_assets.rb` with secret DISCOURSE_ASSETS_RELEASE_TOKEN and publishes GitHub releases on discourse/discourse-assets.
- **Other CI workflows:**
  - `publish-types.yml` publishes `@discourse/types` (`frontend/discourse-types`) to npm (`id-token: write`).
  - `release-handler.yml` cuts branches and tags with GH_PUSH_TOKEN.
  - `tests.yml` runs on pull_request with `contents: read` and installs official plugins and themes from their remotes.

## adversaries

**Rules for every entry point** (`app/controllers/application_controller.rb`)
- **No application-wide login requirement.** Controllers opt in with `requires_login` (`block_if_requires_login`), `ensure_logged_in`, `ensure_staff`, `ensure_admin`, or Guardian checks.
- **Login-required sites.** Site setting `login_required` (default false, `config/site_settings.yml`) is enforced by the global before_action `redirect_to_login_if_required`. That filter returns early for `format.json && is_api?`.
- **Controllers that skip `redirect_to_login_if_required`** (whole controller or listed actions) stay reachable anonymously even on login-required sites:
  - Core: session, users (signup, activation, password reset, email-login, admin-login, check_*), users_email, invites, users/omniauth_callbacks, users/discourse_id#revoke, user_api_keys (new, otp, activate, device create/poll), uploads (show*), user_avatars, stylesheets, theme_javascripts, svg_sprite, highlight_js, extra_locales, static, site (basic_info, statistics), metadata, robots_txt, offline, email, dsa_notices, finish_installation, published_pages#show, mcp, mcp_oauth_metadata, mcp_oauth_tokens, json_api_kit endpoint, qunit, admin/impersonate#destroy.
  - Plugins: chat incoming_webhooks, live livekit_webhooks, github webhooks, subscriptions hooks, patreon webhook, zendesk sync#webhook, workflows webhooks and forms, captcha, adplugin adstxt, discourse-ai shared_ai_conversations#asset and mcp_oauth#client_metadata.
- `WebhooksController` extends `ActionController::Base`, so it has no current user and no login check.
- **CSRF.** ApplicationController calls `protect_from_forgery`. `handle_unverified_request` lets the request through when `is_api? || is_user_api?`. Opt-outs from `verify_authenticity_token`:
  - categories#search; email#unsubscribe (one-click); static (cdn_asset, enter, favicon, llms_txt, service_worker_asset); uploads#show; users#create.
  - user_api_keys device create/poll; users/discourse_id#revoke; omniauth #complete.
  - Whole controllers: webhooks, embed, clicks, user_api_key_clients, mcp, mcp_oauth_tokens, json_api_kit. Also user_avatars show* and published_pages#show.
  - Plugins: the plugin webhooks below, workflows forms, discourse-ai shared conversations #asset.
  - `forgery_protection_origin_check` is false (`config/application.rb`).
- **XHR check.** `check_xhr` rejects requests that are neither JSON nor XHR, unless they are non-GET and carry an API key.

**A1 — Anonymous attacker on the network.** In every row the router and the ApplicationController defaults were read. Checks named by symbol were read in the handler; "not verified" marks what was not.

| Route | Handler | Gate |
|---|---|---|
| `POST /session`, `/session/email-login/:token`, `/session/login-code(/verify)`, `/session/password-reset-code/verify`, `/session/forgot_password`, `/session/passkey/*`, `/session/2fa` | SessionController | `check_local_login_allowed`; RateLimiter by IP and by login (`rate_limit_login`, `rate_limit_login_code_*`; forgot_password 6/h and 3/min); `rate_limit_second_factor!`. `create` was read; the other bodies were not verified |
| `GET /session/sso`, `/session/sso_login` | DiscourseConnect consumer | `enable_discourse_connect`; HMAC-SHA256 compared with `secure_compare` (`DiscourseConnectBase.parse`); `nonce_valid?` and `expire_nonce!`; return_path host check (`domain_redirect_allowed?`) |
| `GET /session/sso_provider` | DiscourseConnect provider | `enable_discourse_connect_provider`; `DiscourseConnectProvider.parse` looks up the secret by return-URL host in `discourse_connect_provider_secrets`; 2FA via `SecondFactor::Actions::DiscourseConnectProvider` |
| `/auth/:provider`, `/auth/:provider/callback` | Users::OmniauthCallbacksController | non-GET request phase checks CSRF (`before_request_phase` → `CSRFTokenVerifier`); the callback is CSRF-exempt; account linking in `ManagedAuthenticator#after_authenticate` (`match_by_email` true, `match_by_username` false); staged users are treated as unregistered |
| `POST /u` (users#create) | signup | CSRF-exempt; raises for a logged-in non-API caller; `UserCreator.registration_error` (invite_only, invite codes); a staged user with the same email is unstaged and reused, inactive |
| `GET /invites/:id`, `PUT /invites/show/:id` | InvitesController | 100/min per IP on show; `ensure_invites_allowed`, `ensure_new_registrations_allowed` |
| `POST /user-api-key-client` | UserApiKeyClientsController#create | per-IP daily limit; scopes must be a subset of `UserApiKeyClientScope.allowed` |
| `POST /user-api-key/device`, `/device/poll`; `GET /user-api-key/new`, `/otp`, `/activate` | UserApiKeysController | `rate_limit_device_*`; issuing keys (`create`, `authorize_device_request`) requires login |
| `POST /auth/discourse_id/revoke` | `DiscourseId::Revoke` | HMAC keyed with SHA256(discourse_id_client_secret); 5-minute timestamp window |
| `POST /webhooks/{aws,mailgun,mailjet,mailpace,mandrill,postmark,sendgrid,sparkpost}` | WebhooksController | each needs its site-setting secret (blank → 406). Mailgun: HMAC plus a Redis replay key. SendGrid: ECDSA. Mandrill: HMAC. SNS: `allowed_topic_arn?` + `authentic?`. Others: a `t` token param. Effect: bounce scores |
| `GET/POST /email/unsubscribe/:key` | EmailController | possession of the UnsubscribeKey; POST limited to 10/min per IP |
| `/embed/{comments,topics,count,status,info}` | EmbedController | `EmbeddableHost.url_allowed?` or a topic_id; reads through TopicView as the current user; an unknown allowed URL enqueues `retrieve_topic` (remote fetch; global 60 s throttle in `TopicRetriever`); `info` needs an API key |
| `/uploads/…`, `/uploads/short-url/:b62`, `/secure-uploads/*` | UploadsController `show*` | open to anonymous unless `prevent_anons_from_downloading_files` (default false); secure uploads → `check_secure_upload_permission`; `show` switches DB to `params[:site]` after `has_db?` |
| Public reads: lists, `/t`, `/p`, `/c`, `/tag(s)`, `/search`, `/u/:username`, `/g`, `/badges`, `/about`, `/site*`, directory, RSS, `.md` variants (`MarkdownEndpoint::RequestConstraint`), sitemap, robots, `/llms.txt` | per-action Guardian | search: `can_search?` = logged in or `allow_anonymous_search` (default true); individual handlers not verified |
| `/message-bus/*` | MessageBus middleware | anonymous refused only when login_required; delivery filtered by the user_ids/group_ids passed at publish time |
| `POST /clicks/track`, `GET /presence/get` | ClicksController, PresenceController | CSRF-exempt; `PresenceChannel#can_view?` |
| `GET /pub/:slug` | PublishedPagesController#show | `enable_page_publishing` (default false); `enforce_login_required!`; non-public pages → `ensure_can_see!` |
| `/dsa/report-illegal-content*` | DsaNoticesController | `ensure_enabled` (not verified further) |
| `/finish-installation/*` | FinishInstallationController | only while `SiteSetting.has_login_hint?` (no admin exists yet) |
| `POST /mcp` | McpController | `mcp_server_enabled` (default false); Origin must equal the issuer origin; bearer token checked by `DiscourseMcp::Authenticator#authenticate!`; rate limits per client and per IP |
| `POST /oauth2/mcp/token`, `/revoke`; `/.well-known/oauth-*`, `/.well-known/openid-configuration` | McpOauthTokensController, McpOauthMetadataController | form-encoded only; code + PKCE verifier or refresh token via `DiscourseMcp::OAuth::TokenIssuer` (internals not verified) |
| `GET /bundle-analysis.json`, `/srv/status` | BundleAnalysisController, forums#status | none |
| `/theme-qunit` | QunitController#index | `can_see_theme_qunit?` (not verified) |
| `/stylesheets/*`, `/theme-javascripts/*`, `/svg-sprite/*`, `/highlight-js/*`, `/extra-locales/*`, `/letter_avatar*`, `/user_avatar/*` | asset controllers | no login (handlers not verified); avatars may proxy remote images via `FileHelper.download` |
| `POST /chat/hooks/:key(/slack)` | Chat::IncomingWebhooksController | lookup by webhook key; 10/min per webhook; posts as the system user |
| `POST /discourse-github/webhooks/github` | DiscourseGithub::WebhooksController | HMAC-SHA256 against `github_webhook_secret` |
| `POST /s/hooks` | DiscourseSubscriptions::HooksController | `Stripe::Webhook.construct_event` with the webhook secret |
| `POST /patreon/webhook` | Patreon::PatreonWebhookController | `valid_signature?` |
| `POST /live/livekit/webhook` | Live::LivekitWebhooksController | `Livekit::WebhookVerifier.verify!` |
| `PUT /zendesk-plugin/sync` | DiscourseZendeskPlugin::SyncController | `token` param compared with `zendesk_incoming_webhook_token` using `!=`; posts as `User.find_by_email(params[:email])` or the system user |
| `POST /discourse-ai/discord/interactions` | DiscourseAi::Discord::BotController | Ed25519 signature; guild allowlist |
| `/workflows/webhooks/*`, `/workflows/waiting/:id/webhook`, `/workflows/form/:uuid`, `/workflows/forms/waiting/:id` | DiscourseWorkflows webhooks and forms | per-node auth mode: none, basic, bearer or header (`AuthenticateNode::SUPPORTED_AUTH_MODES`); rate limited |
| `/discourse-ai/ai-bot/shared-ai-conversations/:key`, `/ai-bot/artifact-shares/:key`, `/ai-bot/artifacts/:id/embed` | AiBot controllers | possession of the share key, or `publicly_embeddable?`; artifacts render as untrusted HTML with `set_security_headers` |

**A2 — Any authenticated user (TL0 and up), group member, or staged user**
- **Content actions:** creates and edits topics, posts, PMs, drafts, bookmarks, flags and reactions under Guardian (`lib/guardian/*`). PMs require `personal_message_enabled_groups` (default admins|moderators|TL1).
- **Uploads** (`UploadsController#create`, `requires_login`): `authorized_extensions` defaults to `jpg|jpeg|png|gif|heic|heif|webp|avif|svg|jxl`; `authorized_extensions_for_staff` is empty by default.
- **Server-side fetches it can trigger:**
  - `/onebox` and `/inline-onebox` (`requires_login`; one preview in flight per user).
  - `/oauth2/mcp/authorize`: requires login, MCP enabled, and `DiscourseMcp::Access.allowed?` (scopes granted to the user's groups; admins are added automatically). It then fetches the client-ID metadata URL (`ClientResolver.resolve!`; policy `any_domain` by default).
- **User API keys:** a user in `user_api_key_allowed_groups` (default admins|moderators|TL0) can create them. `allow_user_api_key_scopes` includes read, write and one_time_password.
- **Chat** (on by default): access is gated by `plugins/chat/lib/chat/guardian_extensions.rb`; routes are in `plugins/chat/config/routes.rb`.
- **When the corresponding plugins are on:**
  - AI bot and helper (agent allowed groups).
  - data-explorer group reports and `GET /data-explorer/queries/:id/run` (`public_run`, `user_can_access_query?` = admin or member of a group the query is shared with). `plugin.rb` registers API key scope `data_explorer/run_queries` for `run` and `public_run`.
  - Workflows forms and buttons; events, assign, boards (ACL).
- **Reviewables** are scoped by `reviewable_post_scope`.
- **Staged users** can see a read-restricted category that has `email_in` set and `email_in_allow_strangers` on (`CategoryGuardian#can_see_category?`).

**A3 — Content author targeting viewers and staff**
- Stored payloads travel through cooked posts, chat messages, bios and user fields, category descriptions (rendered with `html_safe` in `app/views/categories/index.html.erb`), oneboxes, digests and notification emails.
- Posts with `cook_method raw_html` skip cooking (`Post#cook`). Embed imports get that cook method when `embed_support_markdown` is false, which is its default (`app/models/topic_embed.rb`). On expansion their body goes through `PrettyText.sanitize` (`TopicEmbed.expanded_for`).
- `docs/SECURITY.md` singles out preview XSS that runs "in the context of a forum staff member".

**A4 — Malicious remote server**
- **What it can serve:** onebox and inline-onebox targets (`enable_inline_onebox_on_all_domains` default true); remote images (`download_remote_images_to_local` default true); embed host pages (`TopicEmbed.find_remote`, then Readability); avatars; outgoing-webhook receivers (`app/services/web_hook_emitter.rb`); OAuth/OIDC providers; LLM, embedding and MCP servers (discourse-ai); chat-integration targets; theme git repos; MCP client metadata URLs; RSS feeds (rss-polling).
- **SSRF protection, in two tiers:**
  - `FinalDestination#validate_uri_format` (used by `FinalDestination.new…resolve/get` callers) allows only http/https, https only on port 443, http only on port 80 (or the S3 endpoint per `http_port_ok?`), and no IP-literal hosts.
  - `FinalDestination::HTTP#connect` and `FaradayAdapter` (used by webhooks, OIDC, oauth2-basic, workflows, MCP and AI inference clients) apply only `SSRFDetector.lookup_and_filter_ips` and pin the connection to the filtered IPs (`Connector`).
- **Outbound calls that do not go through FinalDestination:**
  - `app/jobs/regular/confirm_sns_subscription.rb` (`Net::HTTP.get`, after the SNS signature check).
  - discourse-ai `tools/google.rb` and `tools/discourse_meta_search.rb`.
  - Slack provider and `slack_command_controller.rb` (`Net::HTTP::Post` to `response_url`); the gitter provider.
  - `call_zapier_webhook.rb` (Excon).
  - The apple-auth JWKS fetch.
  - `lib/discourse_updates.rb`, `lib/discourse_hub.rb`, `app/services/discourse_id/concerns/challenge_flow.rb`.

**A5 — Email sender.** This applies only when `email_in`, `reply_by_email_enabled`, POP3 or IMAP is on; all default to false.
- The sender's identity is the From header (`Email::Receiver#process_internal`).
- A DMARC fail in Authentication-Results sends the post to review (`AuthenticationResults#action`).
- Unknown senders become staged users (`enable_staged_users` default true).
- A reply must carry a reply key whose user matches the sender, unless the mail was forwarded (`process_destination`, `forwarded_reply_key?`).
- Categories accept strangers only with `email_in_allow_strangers`.

**A6 — Integration webhook senders.** These are the shared-secret rows in A1: mail providers, Stripe, GitHub, Patreon, LiveKit, Discord, Zendesk, chat hooks and workflows.

**A7 — Holders of API credentials and third-party apps** (`default_current_user_provider.rb`)
- **Admin API key.**
  - Sent in the `Api-Key` header. It is accepted as a query parameter only on `PARAMETER_API_PATTERNS` (RSS feeds, `users#bookmarks.ics`, `admin/email#handle_mail`) and on plugin-registered routes.
  - A key without a user acts as whoever `Api-Username`, `Api-User-Id` or `Api-User-External-Id` names.
  - `ApiKey#request_allowed?` enforces `allowed_ips` and `ApiKeyScope#permits?` (RouteMatcher). A key with no scopes is unrestricted.
  - Keys are stored SHA-256 hashed (`ApiKey.hash_key`).
  - Extra powers when `is_api?` (admin API key only):
    - `PostsController#create_params` permits `skip_validations`, `import_mode`, `embed_url`, `created_at` and `external_id`.
    - `UploadsController.create_upload` downloads `params[:url]` via `FileHelper.download`.
    - `fetch_target_user` accepts `username`/`external_id`.
- **User API key** (`User-Api-Key` header): checked by `UserApiKeyScope#permits?` and `UserApiKey#ensure_allowed!`, with limits `max_user_api_reqs_per_minute/day`.
- **MCP OAuth bearer token:** `DiscourseMcp::Authenticator` checks scopes, grant_version, client and resource. Tools run with `RequestContext#guardian`, the token user's Guardian.
- **`X-Shared-Session-Key` header:** a key stored in Redis for 7 days, issued when `long_polling_base_url` ≠ "/" (`ApplicationHelper#shared_session_key`). `current_user` honours it on every request, not just message-bus.

**A8 — Prompt injection into AI features** (discourse-ai, off by default)
- Posts, chats and uploads become LLM input.
- Built-in tools act through `Guardian.new(context.user || acting_user)` (`plugins/discourse-ai/lib/agents/tools/tool.rb#guardian`).
- Admin-authored custom tools run JS in MiniRacer (10 MB, 2 s default) with http, llm, upload and Discourse bindings. `ToolRunner#resolve_guardian` can build a Guardian for any username.
- LLM-generated artifacts are served as untrusted HTML (`ArtifactsController#build_untrusted_html`).

**A9 — Another tenant (multisite)**
- Each site has its own database, chosen by Host (RailsMultisite).
- Redis keys are namespaced by `current_db` (`DiscourseRedis#namespace`). `without_namespace` appears on 30 lines in `app/` and `lib/`.
- `/sidekiq` requires `AdminConstraint.new(require_master: true)`, i.e. an admin of the default site. `/logs` (Logster) requires only `AdminConstraint.new`, i.e. an admin of whichever site the Host selects (`config/routes.rb`).
- Uploads switch site by URL path segment (`UploadsController#show`).

**A10 — Staff and admins**
- **Moderators** reach the 14 `Admin::StaffController` controllers: users, groups, reports, dashboard, watched words, screened lists, staff logs, search logs, plugins list, versions, form templates, admin notices. Admin-only actions inside them are gated by `AdminConstraint` on the route plus Guardian (`can_grant_admin?` etc.).
- **Admin capabilities that reach code or data beyond the forum:**
  - Themes: JS and HTML served to all users (`theme_authorized_extensions` includes js and wasm). Git import can use an SSH private key (`lib/theme_store/git_importer.rb`; HTTPS clone hosts are checked by SSRFDetector). The `allowed_theme_repos` GlobalSetting limits which repos can be imported.
  - Backups: download and restore. Restore needs `allow_restore` (default false, an admin-editable site setting) and pipes the dump to `psql` (`lib/backup_restore/database_restorer.rb`).
  - Data-explorer SQL, run under `SET TRANSACTION READ ONLY` with a 10 s statement timeout (`data_explorer.rb`).
  - AI custom tools; the workflows JS sandbox (`js_sandbox.rb`: 100 ms, 50 MB) and its HTTP node (FinalDestination).
  - Impersonation (`Guardian#can_impersonate?`): GlobalSetting `allow_impersonation` is true by default; only developers may impersonate admins.
  - Creating API keys; editing site texts; editing email templates (some template args are cooked with `sanitize: false`, `lib/email/message_builder.rb`).
- The threat model on file says admins are trusted but should not gain OS-level code execution beyond designed features.

**Left out:** about 1,400 route definitions. `config/routes.rb` has about 955 route lines and `plugins/*/config/routes.rb` about 540 more: discourse-ai 111, workflows 92, chat 80, live 47, data-explorer 34, boards 24, events 24, others under 20. Further routes are appended in `plugins/*/plugin.rb` and `plugins/*/lib/**/engine.rb`. The authenticated (A2) and staff/admin (A10) routes among them are summarized above by group, not listed.

## assets

**Data**
- **PMs:** `TopicGuardian#can_see_topic?` requires membership in `topic.all_allowed_users`. Admins see everything unless `suppress_secured_categories_from_admin` is set.
- **Read-restricted categories:** `CategoryGuardian#can_see_category?`, the `Topic.secured` and `Category.secured` scopes, and `filter_allowed_categories`.
- **Whispers, hidden and deleted posts:** `PostGuardian#can_see_post?`, `Post.secured`, `visible_post_types`.
- **Groups and chat:** chat DMs and private channels; group member lists (`can_see_group_members?`).
- **User emails and IPs:** `can_see_emails?`, `can_see_ip?`; `moderators_view_emails` defaults to false.
- **Staff data:** staff notes, reviewables, AI conversations, MCP audit logs.
- **Backups:** the full database plus uploads.

**Credentials and secrets** (kinds and where they are loaded; no values here)
- **`secret_key_base`:** from GlobalSetting or env, otherwise generated and kept in Redis. It encrypts the `_t` auth cookie and salts stored auth tokens (`UserAuthToken.hash_token` = SHA1(token+secret)).
- **Session cookies:**
  - `_t`, set by `set_auth_cookie!`: httponly; `secure` only if `force_https`; SameSite from `same_site_cookies` (default Lax).
  - `_forum_session` (`config/initializers/100-session_store.rb`).
- **Tokens and keys:** API keys and user API keys (SHA-256 hashes in the DB); MCP access and refresh tokens (`McpOauthAccessToken.digest`).
- **In site settings (DB):** DiscourseConnect secrets, OAuth client secrets, webhook secrets, LLM and AI secrets (`ai_secrets`), theme SSH keys, group SMTP/IMAP credentials (not verified).
- **In GlobalSettings:** SMTP, S3, Redis and DB passwords and MaxMind keys (keys listed in `config/discourse_defaults.conf`).
- **CI secrets:** DISCOURSE_ASSETS_RELEASE_TOKEN, GH_PUSH_TOKEN, META_DOCS_API_KEY.

**Capabilities**
- Granting admin and moderator (`Guardian#can_grant_admin?`, `can_grant_moderation?`).
- Impersonation.
- Site settings.
- Code that runs in every visitor's browser (themes).
- Host-level actions through backup restore and theme import.
- Making the server send requests (SSRF).

**Integrity of what is shipped**
- Prebuilt asset tarballs (`download_prebuild_assets!` checks no checksum).
- The `@discourse/types` npm package.
- Release tags.

**Trust boundaries and where they are enforced**
- **Browser ↔ app:**
  - Session lookup: `Auth::DefaultCurrentUserProvider#current_user`. Failed cookie lookups are limited to 10/min per IP (`COOKIE_ATTEMPTS_PER_MIN`). Suspended or inactive users get nil.
  - CSRF: as described above.
  - CSP: `lib/content_security_policy/default.rb` sets `script-src 'strict-dynamic'` with a nonce, `object-src 'none'` and `base-uri 'self'`. It applies to HTML responses only and only while `content_security_policy` is on (default true).
- **Role gates:**
  - Route constraints plus the base controllers, as above.
  - `Guardian#can_see?` returns nil when no `can_see_<class>?` method exists. `can_edit?`, `can_delete?` and `can_create?` return true for any authenticated user when no specific method exists (`Guardian#can_do?`, `#can_create?`).
  - Serializers receive `scope: guardian` (`serialization_scope :guardian`, `serialize_data`).
- **Real time:** MessageBus subscribers get `group_ids` as set in `004-message_bus.rb`; admins get every group id. What each subscriber sees depends on the user_ids/group_ids each publisher passes.
- **Anonymous cache:** `Middleware::AnonymousCache` serves only GET requests without an auth cookie. Its key combines XHR flag, Accept, scheme, Host and REQUEST_URI, the Referer hash on `/embed/`, and `AnonymousCache.build_cache_key` parts (theme ids, color-scheme cookies; the rest not verified).
- **Server → network:** `SSRFDetector` drops private and reserved ranges and `blocked_ip_blocks`. It skips filtering for hosts in `allowed_internal_hosts`, the CDN hosts and the site's own host.
- **Server → untrusted-format parsers:**
  - V8 (MiniRacer) for markdown (25 s timeout, `PrettyText.create_es6_context`), AI tools and workflows.
  - ImageMagick under `policy.xml`: coders limited to GIF, JPEG, PNG, WEBP, AVIF, HEIC/HEIF, MSVG, MVG, XC, ICC and INFO; no delegates; `@*`, `/etc/*` and `../` paths denied. `003-imagemagick.rb` enforces it through `MAGICK_CONFIGURE_PATH` and refuses to boot if that variable is set externally.
  - The libvips worker: `Landlock.fork` with read/write allowlists, rlimits, and seccomp denying network and child processes on Linux. `on_unsupported: :run_without_landlock` runs it unsandboxed where Landlock is unavailable.
  - SVG uploads are pruned to `ALLOWED_SVG_ELEMENTS` (`UploadCreator#clean_svg!`).
- **Serving uploads:** `send_file_local_upload` sets `Content-Security-Policy: sandbox;` and uses attachment disposition unless `FileHelper.is_inline_safe?`. The nginx sample adds `Content-Disposition: attachment` for `.svg` under `/uploads/`.
- **Site ↔ site:** the RailsMultisite DB switch; `EnforceHostname`, which pins Host to the site's hostnames and clears X-Forwarded-Host; the Redis namespace.

**Priorities carried over from the threat model on file.** The code above still bears these out.
1. Authorization leaks of private content.
2. Account integrity: authentication bypass, SSO/OAuth, 2FA, invites, privilege escalation.
3. Stored XSS and CSP bypass.
4. SSRF.
5. Server compromise: RCE, SQL injection, path traversal in uploads, backups and themes.
6. Availability: expensive queries, regex DoS, rate-limit gaps.

## out-of-scope
What follows reports the repositories' own statements and exempts nothing from the audit.


**`docs/SECURITY.md`**
- Reports go to HackerOne. Emailed reports are unlikely to be acted on "unless they come from a trusted source", and "Theoretical reports without a proof of concept are not accepted."
- "API calls using the secret API bypass CSRF checks."
- CSP "can be switched off in the site settings, but it is default on".
- For DDoS protection, "we recommend placing HAProxy in front".
- "We strongly recommend that the various Discourse processes (web server, sidekiq) run under a non-elevated account"; the Docker image does this.
- It says the server-side sanitizer is "implemented using the Sanitize gem" in `lib/pretty_text.rb`. In the code, `PrettyText.sanitize` calls xss.js in V8; the Sanitize gem is used for oneboxes and a few other paths.

**Other repository documents**
- `docs/INSTALL.md`: only Docker installs are supported.
- `docs/PLUGINS.md`: "If you want to be safe, use only plugins on this list of Official Plugins" (`lib/plugin/metadata.rb`, `config/official_plugins.json`).
- `config/environments/production.rb` comment: "developers have god like rights and may impersonate anyone in the system". Its line "normal admins may only impersonate other moderators" is narrower than `Guardian#can_impersonate?`, which lets admins impersonate any non-admin.
- `session_controller.rb` `become`: "For use in development mode only… NEVER allow this to work in production". It is defined only `if !Rails.env.production?` and also needs `DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE=1`.
- `lib/auth/managed_authenticator.rb`: matching by username "could be insecure, so it's disabled by default".
- `lib/pretty_text.rb`: "Be careful disabling sanitization. We allow for custom emails" (`sanitize: false`).

**Left to the deployer** (defaults from `config/site_settings.yml` and `config/discourse_defaults.conf`)
- A private forum needs `login_required` (off by default).
- HTTPS-only cookies need `force_https` (off).
- `secure_uploads` (off).
- `enable_cors` and `cors_origin` (off).
- `allowed_internal_hosts` and `blocked_ip_blocks` (empty).
- `allowed_theme_repos` (empty, so any repo is allowed).

**Contributor guidance.** `AI-AGENTS.md` (symlinked as CLAUDE.md, GEMINI.md and AGENTS.md) and `.github/instructions/copilot.instructions.md` tell contributors to use Guardian, escape with `{{}}` and keep CSRF. They exclude nothing.

## production

Reviewed whole at e08ed05b4b1ef773b2de7948a8f88a7c182a3520, because the threat model on file gave no commit to diff from. The project covers the whole repository. Each area below was at least listed; the files cited elsewhere in this document were read.

- `app/` — production: Rails controllers, models, serializers, jobs, services, views.
- `lib/` — production. Tooling inside it: `lib/discourse_dev`, `lib/faker`, `lib/autospec`, `lib/turbo_tests`, `lib/generators`, `lib/release_utils`. `lib/tasks` holds rake tasks the operator runs at deploy and for admin work.
- `config/` — production config: routes, initializers, site settings, locales, and sample configs for nginx, multisite and unicorn.
- `db/` — production: migrations and `structure.sql` run on deploy; `db/fixtures` is seed data; `api_test_seeds.rb` is for tests.
- `plugins/` — production: bundled, each enabled by a site setting. Their `spec/` and `test/` folders and `plugins/discourse-ai/evals` are tests and tooling. `styleguide` is a developer UI, off by default.
- `frontend/` — production: the Ember app is built into served assets.
  - Tests: `frontend/discourse/tests`, `type-tests`, `frontend/playwright-runner`.
  - Published to npm: `frontend/discourse-types`.
  - Loaded server-side in V8: `frontend/asset-processor`, `frontend/pretty-text-processor`.
- `public/` — production static files (error pages and the like).
- `themes/` — production system themes (foundation, horizon), installed by `lib/system_themes_manager.rb`.
- `vendor/` — production vendored assets (svg-icons, an ICC profile).
- `script/` — mostly tooling: importers, bulk_import, benchmarks, memory tools, and `publish_built_assets.rb`, which CI runs. Two scripts run in production: `discourse_vips_worker` at runtime and `assemble_ember_build.rb` in the asset build.
- `bin/` — wrappers for development and operations (rails, rake, pitchfork, docker, lint).
- `migrations/` — tooling: import and converter gems in the optional `:migrations` Gemfile group (`migrations/README.md`).
- `spec/`, `test/` — tests.
- `docs/` — documentation. `docs/developer-guides` is synced to meta by CI (`developer-docs-publish.yml`).
- `patches/` — build: pnpm patches applied to shipped dependencies, including `xss@1.0.15.patch` for the sanitizer library.
- `.github/` — CI and release workflows.
- `images/` — README images.
- `stylelint-rules/` — lint tooling.
- `log/` — empty runtime directory.
- `.devcontainer`, `.vscode`, `.zed`, `.skills`, `.agents`, `.claude`, `.cursor` — developer and agent tooling.
- Root files:
  - `Gemfile`, `Gemfile.lock`, `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml` — production dependency manifests.
  - `config.ru`, `Rakefile` — production.
  - `lefthook.yml`, `translator.yml`, `.licensed.yml` and the lint configs — tooling.

## facts

**Security policy.** `docs/SECURITY.md` (HackerOne; team@discourse.org). There is no SECURITY.md at the root; README.md links to the docs one.

**Templates and escaping**
- Server views are ERB with Rails auto-escaping. `app/views` has 42 `html_safe`/`raw` uses, mostly on cooked post HTML (`topics/show.html.erb`, `published_pages/show.html.erb`, `list/list.erb` excerpts) and on translations.
- Client templates are Glimmer (`.gjs`/`.gts`; there are no `.hbs` files). `{{}}` escapes; `trustHTML` from `@ember/template` bypasses escaping and appears in about 256 non-test files.
- Post HTML comes from markdown-it plus the xss.js allowlist in V8. The allowlist lives in `frontend/pretty-text/addon/allow-lister.js` and the `allowed_iframes` site setting. Hrefs are limited by `hrefAllowed` plus `allowed_href_schemes`.

**Serialization**
- JSON uses Oj in `compat` mode (`config/initializers/100-oj.rb`) through MultiJson.
- Cookies use the MessagePack serializer; the key generator digest is SHA1 (`config/application.rb`).
- YAML columns permit only Hash, HashWithIndifferentAccess, Time and Symbol (`yaml_column_permitted_classes`).
- YAML from users and admins goes through `YAML.safe_load` (`lib/theme_settings_parser.rb`, `lib/theme_translation_parser.rb`, `app/models/form_template.rb`, `app/services/site_settings_task.rb`). `YAML.load_file` is used only on repository files (`lib/site_settings/yaml_loader.rb`, locales, email templates).
- `Marshal.load` reads cache values from Redis (`lib/cache.rb`). The zendesk plugin stores OAuth tokens with `Marshal.dump`.
- DiscourseConnect payloads are Base64 query strings signed with HMAC-SHA256.
- The vips worker exchanges MessagePack over a Unix socket.

**Authentication and sessions**
- The `_t` cookie is encrypted. v1 carries token, user_id, username, trust_level and issued_at; the legacy 32-character v0 form is still accepted (`find_v0_auth_cookie`).
- Tokens rotate every 10 minutes (`UserAuthToken::ROTATE_TIME`), with at most 60 sessions per user (`MAX_SESSION_COUNT`).
- `maximum_session_age` defaults to 1440 h; `persistent_sessions` defaults to true.
- Passwords use PBKDF2-SHA256 with 600,000 iterations (`config/application.rb`, `lib/password_hasher.rb`).
- 2FA: TOTP, security keys and backup codes. `enforce_second_factor` defaults to "no"; `enable_passkeys` defaults to true.
- Also supported: API keys, user API keys, MCP OAuth with PKCE, DiscourseConnect, and OmniAuth (Google, GitHub, Facebook, Twitter, Discord, LinkedIn and Discourse ID in `lib/auth`, more via plugins).

**Defaults that change exposure** (`config/site_settings.yml`)
- Access: `login_required` false; `invite_only` false; `must_approve_users` false; `enable_local_logins` true; `allow_anonymous_search` true.
- Browser protections: `content_security_policy` true; `force_https` false; `same_site_cookies` Lax; `allow_embedding_site_in_an_iframe` false; `embed_any_origin` false.
- Uploads and remote content: `secure_uploads` false; `prevent_anons_from_downloading_files` false; `download_remote_images_to_local` true; `enable_inline_onebox_on_all_domains` true; `allowed_onebox_iframes` "*".
- Features: `enable_safe_mode` true; `enable_page_publishing` false; `enable_backups` true; `allow_restore` false; `enable_badge_sql` false (hidden).
- MCP: `mcp_server_enabled` false; `mcp_oauth_client_id_metadata_policy` any_domain.
- SSO and email: `enable_discourse_connect` false; `enable_discourse_connect_provider` false; `enable_staged_users` true; `email_in` false; `reply_by_email_enabled` false.
- Groups: `user_api_key_allowed_groups` admins|mods|TL0; `personal_message_enabled_groups` admins|mods|TL1.

**GlobalSetting defaults** (`config/discourse_defaults.conf`)
- `allow_impersonation` true.
- `load_mini_profiler` true. Access is gated by `mini_profiler_enabled?` to developers or holders of the `_mp_auth` cookie from `/dev-mode`.
- `enable_cors` false; `serve_static_assets` false.
- Per-IP limits: `max_reqs_per_ip_per_minute` 200 and `max_reqs_per_ip_per_10_seconds` 50, in mode block; TL1 and above skip them (`skip_per_ip_rate_limit_trust_level`).
- API limits: `max_admin_api_reqs_per_minute` 60; `max_user_api_reqs_per_minute` 50 and `max_user_api_reqs_per_day` 4000.
- `regex_timeout_seconds` 2 (`100-regex-timeout.rb`); `db_prepared_statements` false.

**Build and hardening**
- Rails `load_defaults 8.1`.
- `Rack::Lock`, `Rack::Runtime` and `Rack::ETag` are removed from the middleware stack.
- `mini_racer_single_threaded` is true.
- The ImageMagick policy, the libvips Landlock/seccomp worker and the MiniRacer limits are described under assets.

**Where things are defined**
- Routes: `config/routes.rb`, `plugins/*/config/routes.rb`, `plugins/*/plugin.rb`, `plugins/*/lib/**/engine.rb`.
- Schema: `db/structure.sql`, `db/migrate`, `db/post_migrate`, `plugins/*/db/`.
- Permissions: `lib/guardian.rb`, `lib/guardian/`, plugin Guardian extensions, `lib/admin_constraint.rb`, `lib/staff_constraint.rb`.
- API scopes: `app/models/api_key_scope.rb`, `app/models/user_api_key_scope.rb`, plus plugin `add_api_key_scope`. MCP scopes: `lib/discourse_mcp/`.
- Site settings: `config/site_settings.yml`, `plugins/*/config/settings.yml`.
- ACL: `lib/acl/`.

**Languages** (git-tracked line counts)
- All files: Ruby 1.53M (59%), JavaScript 900k (`.js` 425k plus `.gjs` 475k; 35%), SCSS 106k (4%), TypeScript 53k (`.ts`/`.gts`; 2%), ERB 5k.
- Excluding `spec/` and `test(s)/` directories: Ruby 610k (47%), JS/GJS 527k (41%), SCSS 106k (8%), TS 51k (4%).


<!-- written at these commits:
e08ed05b4b1ef773b2de7948a8f88a7c182a3520 https://github.com/cx-benchmark/discourse
-->
