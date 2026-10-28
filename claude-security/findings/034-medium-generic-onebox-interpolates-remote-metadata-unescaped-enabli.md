# Generic onebox interpolates remote metadata unescaped, enabling stored HTML/CSS injection in posts

| Field | Value |
|---|---|
| ID | `find_01CiUUTg5FQrKFcSMge3n8we` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-79 — HTML injection |
| Created | 2026-10-27T21:23:31.362118Z |
| Claude Security | https://claude.ai/security/findings/find_01CiUUTg5FQrKFcSMge3n8we |

## Description

A registered user who controls a public web page can inject page-wide HTML and CSS into a forum post. Every reader of the topic gets it. The impact is limited because script execution is blocked. The attack needs only a link to the attacker's page on its own line in a post. The cause is `AllowlistedGenericOnebox`, which puts unescaped page metadata into HTML attributes, and a sanitizer that keeps `<style>`.

```mermaid
flowchart TD
  n1["registered user with a public page"]
  n2["remote page meta tags"]
  n3["AllowlistedGenericOnebox image_html, video_html, card_html"]
  n4["HTML escaping of remote values"]
  n5["Preview#sanitize with ONEBOX config"]
  n6["post.cooked shown to every reader"]
  n1 -->|"controls and links to it"| n2
  n2 -->|"metadata with markup fetched"| n3
  n4 -->|"not applied"| n3
  n3 -->|"emits injected markup"| n5
  n5 -->|"keeps style elements and attributes"| n6
  classDef actor stroke:#2563eb,stroke-width:2px
  classDef vulnerable_code stroke:#dc2626,stroke-width:2px
  classDef existing_control stroke:#16a34a,stroke-width:2px
  classDef missing_control stroke:#dc2626,stroke-width:2px,stroke-dasharray:5 5
  classDef asset stroke:#9333ea,stroke-width:2px
  classDef component stroke:#6b7280,stroke-width:1px
  class n1 actor
  class n2 component
  class n3 vulnerable_code
  class n4 missing_control
  class n5 existing_control
  class n6 asset
```

1. **attacker** publishes a page whose meta tags hold markup. The page sets `og:type=photo`, `og:image`, and `twitter:description` (or an untruncated `twitter:image:width`) to `'><style>body{display:none}</style><img alt='`.
2. **attacker** posts the page URL on its own line. The report says any registered user who can post a link can do this, and TL0 may post 2.
3. **`StandardEmbed#get_twitter`** copies the `twitter:*` meta values into `@raw` unchanged. `set_twitter_data_on_raw` uses them when the matching `og:*` key is absent, and they are not sanitized. ([`lib/onebox/engine/standard_embed.rb:78-94`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/standard_embed.rb#L78-L94))
4. **`Onebox::Normalizer#sanitize_value`** decodes HTML entities after `Sanitize.fragment`. Double-encoded `<` and `>` in an `og:*` value become raw characters. This is a second source of raw markup. ([`lib/onebox/normalizer.rb:35-41`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/normalizer.rb#L35-L41))
5. **`image_html`** interpolates the value into `alt='...'` without escaping. A value containing `'>` closes the `<img>` tag and adds new elements. `video_html` does the same with `title`, and `card_html` with `player_width` and `player_height`. ([`lib/onebox/engine/allowlisted_generic_onebox.rb:273-283`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/allowlisted_generic_onebox.rb#L273-L283))
6. **`Onebox::Preview#sanitize`** keeps the injected markup. `SanitizeConfig::DISCOURSE_ONEBOX` is built on Sanitize `RELAXED`, which allows `<style>` elements, `style`, `id` and `class` attributes, and `<a href>` to http(s). ([`lib/onebox/sanitize_config.rb:9-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/sanitize_config.rb#L9-L45))
7. **`post_process_oneboxes`** stores the onebox in `post.cooked` with no further sanitization. The client then writes it into the page with `innerHTML`. ([`lib/cooked_processor_mixin.rb:13-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/cooked_processor_mixin.rb#L13-L45))
8. **reader's browser** applies the injected CSS to the whole page. The default CSP has no `style-src`, so the rules and `style` attributes take effect. ([`lib/content_security_policy/default.rb:9-23`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/content_security_policy/default.rb#L9-L23))

## Assessment

The attacker is any registered user who can post a link (TL0 may post 2) and who controls a public web page. The page sets `og:type=photo`, `og:image`, and `twitter:description` (or an untruncated `twitter:image:width`) to `'><style>body{display:none}</style><img alt='`. Other routes to the same flaw are `og:type=video.*` with an mp4 `og:video` (via `video_html`), `twitter:player:width` and `twitter:player:height` (via `card_html`), and double-encoded `<` and `>` in `og:description` or `og:title`. The attacker posts the URL on its own line and no victim action is needed. The result is stored and applies to every reader who opens the topic.

Impact: The attacker can deface or blank the topic for all readers and hide parts of the interface. They can lay an invisible full-page `position:fixed` link over the page for phishing. They can use attribute-selector `url()` beacons to learn limited facts about a viewer, such as staff status or username. The impact is limited because CSP `script-src` and Sanitize block script, and `@import` is stripped.

## Recommendation

(1) `image_html`, `video_html` and `card_html` in `AllowlistedGenericOnebox` build HTML attributes by string interpolation of remote metadata without HTML escaping.

Fix criteria: All remote-derived values placed into onebox HTML, in attributes or text, are HTML-escaped (for example with `ERB::Util.html_escape` or `CGI.escapeHTML`) or emitted through the Mustache `{{ }}` templates. A page whose `twitter:description` or `og:description` contains `'><style>` must yield an `<img>` whose `alt` attribute contains that literal text and no additional elements.

(2) `StandardEmbed#get_twitter` stores `twitter:*` meta values raw, and `Normalizer#sanitize_value` decodes entities after sanitizing. So sanitized metadata can still contain `<`, `>` and quotes.

Fix criteria: Twitter-card values go through the same normalization as OpenGraph values. Normalization does not bring markup characters back after sanitization: there is no entity decode after `Sanitize.fragment`, or the value is escaped on output. A test with triple-encoded `&amp;amp;lt;` in `og:description` shows that the rendered onebox contains no raw `<`.

(3) The onebox sanitizer config (`SanitizeConfig::ONEBOX`, built on Sanitize `RELAXED`) permits `<style>` elements, `style` and `id` attributes on all elements, and `<embed src>`. Any markup that reaches it can restyle the whole page.

Fix criteria: The onebox sanitizer removes `<style>` elements, `<embed>` and the `id` attribute. It either drops the `style` attribute or limits it to the few layout properties the templates need (`--aspect-ratio`, `float`, `clear`, `max-width`). A sanitized onebox then cannot contain rules that affect elements outside the onebox, or `position:fixed` and `z-index` overlays.

## Evidence

**https://github.com/cx-benchmark/discourse**

- [`lib/onebox/engine/allowlisted_generic_onebox.rb:273-283`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/allowlisted_generic_onebox.rb#L273-L283)
- [`lib/onebox/engine/allowlisted_generic_onebox.rb:285-300`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/allowlisted_generic_onebox.rb#L285-L300)
- [`lib/onebox/engine/allowlisted_generic_onebox.rb:251-261`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/allowlisted_generic_onebox.rb#L251-L261)
- [`lib/onebox/engine/standard_embed.rb:78-94`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/standard_embed.rb#L78-L94)
- [`lib/onebox/normalizer.rb:35-41`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/normalizer.rb#L35-L41)
- [`lib/onebox/sanitize_config.rb:9-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/sanitize_config.rb#L9-L45)
- [`lib/onebox/preview.rb:26-29`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/preview.rb#L26-L29)
- [`lib/cooked_processor_mixin.rb:13-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/cooked_processor_mixin.rb#L13-L45)
- [`lib/content_security_policy/default.rb:9-23`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/content_security_policy/default.rb#L9-L23)

