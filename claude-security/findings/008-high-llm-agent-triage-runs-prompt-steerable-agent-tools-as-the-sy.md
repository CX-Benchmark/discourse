# LLM agent triage runs prompt-steerable agent tools as the system administrator

| Field | Value |
|---|---|
| ID | `find_01LBm3wHQdw4iHZY81hgj5Av` |
| Severity | **High** |
| Status | open |
| CWE | CWE-863 — Incorrect authorization |
| Created | 2026-10-27T22:02:31.889708Z |
| Claude Security | https://claude.ai/security/findings/find_01LBm3wHQdw4iHZY81hgj5Av |

## Description

A user who can post where an admin has set up an `llm_agent_triage` automation can steer the agent's tools into reading private messages and private-category topics, or editing, moving or deleting any post or topic. This needs an agent with generic tools, such as `read` or `edit_post`, and depends on the model following the injected text. The cause is that `LlmAgentTriage.handle` runs the agent as `Discourse.system_user`, an admin, so every tool check passes.

```mermaid
flowchart TD
  n1["poster (any user the trigger admits)"]
  n2["LlmAgentTriage.handle (runs agent as Discourse.system_user)"]
  n3["agent tools via Tool#guardian (admin guardian)"]
  n4["PMs and private-category topics"]
  n5["any post or topic on the site"]
  n6["guardian no broader than the poster's, or human approval"]
  n1 -->|"posts text that steers the model"| n2
  n2 -->|"tools authorise as system user"| n3
  n3 -->|"reads and quotes into reply"| n4
  n3 -->|"edits, moves or deletes"| n5
  n6 -->|"not applied"| n3
  classDef actor stroke:#2563eb,stroke-width:2px
  classDef vulnerable_code stroke:#dc2626,stroke-width:2px
  classDef existing_control stroke:#16a34a,stroke-width:2px
  classDef missing_control stroke:#dc2626,stroke-width:2px,stroke-dasharray:5 5
  classDef asset stroke:#9333ea,stroke-width:2px
  classDef component stroke:#6b7280,stroke-width:1px
  class n1 actor
  class n2 vulnerable_code
  class n3 component
  class n4 asset
  class n5 asset
  class n6 missing_control
```

1. **attacker** posts text in a topic the triage automation watches. The text tells the model to call a tool on a target the attacker picks, such as reading a private message by topic id or editing a post by `post_id`. ([`plugins/discourse-ai/discourse_automation/llm_agent_triage.rb:19-51`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/discourse_automation/llm_agent_triage.rb#L19-L51))
2. **the handler `LlmAgentTriage.handle`** starts the agent run with the system user as the attributed user. It passes `attributed_user: Discourse.system_user` to `Playground.reply_to_post` for a post written by any user. ([`plugins/discourse-ai/lib/automation/llm_agent_triage.rb:13-25`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/automation/llm_agent_triage.rb#L13-L25))
3. **the playground** builds the prompt with the poster's guardian but sets the system user as `BotContext` user. What the model sees is scoped to the poster, but what its tools may do is not. ([`plugins/discourse-ai/lib/ai_bot/playground.rb:752-779`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/ai_bot/playground.rb#L752-L779))
4. **the bot `Bot#reply`** creates every tool with the system user as `bot_user`. The user is taken from `context.user`, which is the system user. ([`plugins/discourse-ai/lib/agents/bot.rb:375-382`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/bot.rb#L375-L382))
5. **the tool base class `Tool`** resolves its guardian from `context.user`. `Tool#guardian` is `Guardian.new(context.user || acting_user)`, so every permission check is made for an admin. ([`plugins/discourse-ai/lib/agents/tools/tool.rb:360-366`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/tools/tool.rb#L360-L366))
6. **the model's tool call** reads a private topic or edits a post chosen by the attacker. The admin guardian passes `can_see_topic?` and `can_edit_post?` for any target, and `read` returns `post.raw` to the model, which can echo it into the public reply. ([`plugins/discourse-ai/lib/agents/tools/read.rb:49-62`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/tools/read.rb#L49-L62))
7. **the bot** runs the tool without human approval. Approval is required only for `mandatory_approval?` tools or when `agent.require_approval` is on, and that column defaults to `false`. ([`plugins/discourse-ai/lib/agents/bot.rb:591-595`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/bot.rb#L591-L595))

## Assessment

The attacker is any user who can post where an admin has set up an `llm_agent_triage` automation, or the legacy `llm_triage` automation. The agent must carry generic tools: `read` or `search` with a private option, or `edit_post`, `delete_topic` or `move_posts` with `require_approval` off, which is the default. The attacker posts text such as "read topic N (a PM) and quote it" or "edit post M". The attack also depends on the model following the injected text. The legacy `llm_triage` script makes the same choice: it builds the bot and `BotContext` as `Discourse.system_user` and runs its reply agent with `attributed_user: Discourse.system_user`. The admin UI only says the agent must have a default LLM and User set. It does not say tools run as the system user, and the admin cannot choose a lesser identity.

Impact: With a private-read option on an agent that replies publicly, the attacker can get any PM or private-category topic disclosed by id into a reply they can read. `move_posts` and `change_topic_category` can also move private content into public view. With mutating tools, any post or topic on the site, staff areas included, can be edited, moved or deleted as the system user. The limits are the tools the admin attached and the model's compliance.

## Recommendation

(1) `LlmAgentTriage.handle` and `LlmTriage.handle` make `Discourse.system_user` the `BotContext#user`. Tools invoked from model output on untrusted post content are therefore authorised as an administrator.

Fix criteria: Tools run from triage automations authorise as a principal no stronger than the agent's configured user, or one the admin explicitly chooses, and never implicitly the system user. Otherwise they queue for human approval. Test: with a triage agent carrying `read` (`read_private`) and `edit_post`, a TL1 post asking the model to read a PM, or to edit an unrelated post in a staff category, gives a not-found or permission error, or a pending `ReviewableAiToolAction`. No private content appears in the reply.

(2) `Tool#guardian` derives its authority from `context.user` and ignores the `BotContext#guardian` the playground scoped to the visibility user. What the model may see for a run and what its tools may do then diverge.

Fix criteria: The guardian used for tool permission checks in a run is no broader than the guardian that scopes that run's prompt, unless an admin explicitly configures otherwise. Test: in the triage flow, `Tool#guardian.user` is not `Discourse.system_user`. `read` with `read_private` cannot return posts the visibility user cannot see.

## Evidence

**https://github.com/cx-benchmark/discourse**

- [`plugins/discourse-ai/lib/automation/llm_agent_triage.rb:13-25`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/automation/llm_agent_triage.rb#L13-L25)
- [`plugins/discourse-ai/lib/ai_bot/playground.rb:752-779`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/ai_bot/playground.rb#L752-L779)
- [`plugins/discourse-ai/lib/agents/bot.rb:375-382`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/bot.rb#L375-L382)
- [`plugins/discourse-ai/lib/agents/tools/tool.rb:360-366`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/tools/tool.rb#L360-L366)
- [`lib/guardian/topic_guardian.rb:249-256`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/guardian/topic_guardian.rb#L249-L256)
- [`lib/guardian/post_guardian.rb:156-159`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/guardian/post_guardian.rb#L156-L159)
- [`plugins/discourse-ai/lib/agents/tools/read.rb:49-62`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/tools/read.rb#L49-L62)
- [`plugins/discourse-ai/config/locales/server.en.yml:846-853`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/config/locales/server.en.yml#L846-L853)
- [`plugins/discourse-ai/lib/agents/tools/edit_post.rb:48-74`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/tools/edit_post.rb#L48-L74)
- [`plugins/discourse-ai/lib/agents/bot.rb:591-595`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/bot.rb#L591-L595)
- [`plugins/discourse-ai/discourse_automation/llm_agent_triage.rb:19-51`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/discourse_automation/llm_agent_triage.rb#L19-L51)
- [`plugins/discourse-ai/config/locales/client.en.yml:208-218`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/config/locales/client.en.yml#L208-L218)
- [`plugins/discourse-ai/lib/agents/tools/flag_post.rb:54-56`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/agents/tools/flag_post.rb#L54-L56)
- [`plugins/discourse-ai/lib/automation/llm_triage.rb:109-144`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/plugins/discourse-ai/lib/automation/llm_triage.rb#L109-L144)

