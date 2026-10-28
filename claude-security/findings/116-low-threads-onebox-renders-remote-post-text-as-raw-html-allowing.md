# Threads onebox renders remote post text as raw HTML, allowing stored CSS/HTML injection

| Field | Value |
|---|---|
| ID | `find_01BrhYyxtgr5uE94ZQDDxNfW` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-79 — HTML injection |
| Created | 2026-10-27T21:25:53.935358Z |
| Claude Security | https://claude.ai/security/findings/find_01BrhYyxtgr5uE94ZQDDxNfW |

## Description

A Threads user with a Discourse account that can post a link can inject their own CSS and HTML into a forum post. Every reader of the topic gets it. Scripts do not run, but the attacker can restyle or hide page content and overlay an invisible link. The cause is `ThreadsStatusOnebox#description`, which puts remote post text into the template unescaped.

```mermaid
flowchart TD
  n1["Threads user with a Discourse account"]
  n2["ThreadsStatusOnebox description and threadsstatus.mustache"]
  n3["Normalizer get (Sanitize.fragment on remote values)"]
  n4["Preview sanitize with DISCOURSE_ONEBOX (keeps style element)"]
  n5["post.cooked shown to every reader"]
  n1 -->|"posts a threads.net link whose text holds markup"| n2
  n3 -->|"not used"| n2
  n2 -->|"passes unescaped HTML"| n4
  n4 -->|"keeps style and link markup"| n5
  classDef actor stroke:#2563eb,stroke-width:2px
  classDef vulnerable_code stroke:#dc2626,stroke-width:2px
  classDef existing_control stroke:#16a34a,stroke-width:2px
  classDef missing_control stroke:#dc2626,stroke-width:2px,stroke-dasharray:5 5
  classDef asset stroke:#9333ea,stroke-width:2px
  classDef component stroke:#6b7280,stroke-width:1px
  class n1 actor
  class n2 vulnerable_code
  class n3 missing_control
  class n4 existing_control
  class n5 asset
```

1. **Attacker** publishes a Threads post containing markup. The text can be a `<style>` element or an `<a>` with a `style` attribute such as `position:fixed` and `z-index:9999`. Threads encodes `og:description` only once, so a typed `<` is served as `&lt;`. ([`spec/fixtures/onebox/threadsstatus_without_image.response:1`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/spec/fixtures/onebox/threadsstatus_without_image.response#L1))
2. **Attacker** posts the `threads.net/t/…` URL in a Discourse topic. `CookedPostProcessor` then builds a onebox for the link with `ThreadsStatusOnebox`. ([`lib/cooked_processor_mixin.rb:13-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/cooked_processor_mixin.rb#L13-L45))
3. **`OpenGraph#extract`** stores the `og:description` value after Nokogiri decodes it. The `&lt;` entity becomes a literal `<`, so the post text now reads as markup. ([`lib/onebox/open_graph.rb:27-47`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/open_graph.rb#L27-L47))
4. **the engine `ThreadsStatusOnebox`** reads the raw `@og[:description]` and adds mention links with `linkify_mentions`. The engine reads `OpenGraph#data` directly and skips the sanitizing `Normalizer#get`. Nothing escapes the text. ([`lib/onebox/engine/threads_status_onebox.rb:35-38`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/threads_status_onebox.rb#L35-L38))
5. **the template `threadsstatus.mustache`** prints the description with `{{{description}}}`. The triple mustache outputs the value without HTML escaping. ([`lib/onebox/templates/threadsstatus.mustache:6`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/templates/threadsstatus.mustache#L6))
6. **`Onebox::Preview#sanitize`** filters the HTML with `DISCOURSE_ONEBOX` but keeps the injected markup. This config is built on Sanitize `RELAXED`. It keeps top-level `<style>` elements, `style`/`id`/`class` attributes, and http(s) `<a href>` and `<img src>`. ([`lib/onebox/sanitize_config.rb:7-13`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/sanitize_config.rb#L7-L13))
7. **`Oneboxer.apply`** writes the fragment into `post.cooked`. The injected markup is now stored with the post. ([`lib/cooked_processor_mixin.rb:13-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/cooked_processor_mixin.rb#L13-L45))
8. **the reader's browser** renders the cooked HTML with `trustHTML` and applies the injected styles to the whole page. The default CSP sets no `style-src`, so the stylesheet is allowed. ([`frontend/discourse/app/components/post/cooked-html.gjs:201`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/frontend/discourse/app/components/post/cooked-html.gjs#L201))

## Assessment

The attacker needs a Threads post and a Discourse account that can post a link (the report says TL0 may post 2). They publish a Threads post with markup, for example `<style>body{display:none}</style>`, or an `<a>` with a `style` attribute such as `position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999` that points to a phishing page. Then they post its `threads.net/t/…` URL in a topic. This only works while `threads.net` still serves post pages with server-rendered `og:description` in the format the engine expects. If it redirects to `threads.com`, `FinalDestination` follows the redirect and this engine, which matches only `threads.net`, is never chosen. The Twitter/X onebox is not affected. X encodes `og:description` twice, so a typed `<` stays text.

Impact: The attacker can restyle or hide any element on pages that show the post, for example blank the topic, hide controls or show fake notices. They can also lay an invisible full-page link to a page they control over the content. `background-image` URLs they choose leak viewers' IP addresses, and attribute selectors can probe a few attribute values. Scripts cannot run, because `script-src` and the sanitizer block them and `object-src 'none'` blocks `<embed>`, so this is stored HTML/CSS injection only. It is still more than users may do, because the post sanitizer does not let them post `<style>` or arbitrary `style` attributes.

## Recommendation

(1) `ThreadsStatusOnebox#description` takes the raw `OpenGraph#data` value and `threadsstatus.mustache` prints it with `{{{ }}}`. Post text written by a third party is therefore parsed as HTML.

Fix criteria: Threads post text is HTML-escaped before the mention links are added, or it is rendered with `{{ }}` and the links are built from the escaped text. A Threads post containing `<style>x</style><a href=...>` renders as literal text inside the onebox and creates no new elements.

(2) `Onebox::SanitizeConfig::ONEBOX` inherits Sanitize `RELAXED`, which keeps top-level `<style>` and the `style` attribute on every element. Any engine that lets markup through can therefore restyle the whole page.

Fix criteria: Sanitized onebox output never contains a `<style>` element. `style` attributes are removed or limited to the properties the templates need, such as `float`, `clear` and `--aspect-ratio`. A fragment containing `<style>` or `position:fixed` comes out of the sanitizer without them.

## Evidence

**https://github.com/cx-benchmark/discourse**

- [`lib/onebox/templates/threadsstatus.mustache:6`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/templates/threadsstatus.mustache#L6)
- [`lib/onebox/engine/threads_status_onebox.rb:35-38`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/threads_status_onebox.rb#L35-L38)
- [`lib/onebox/engine/threads_status_onebox.rb:68-73`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/threads_status_onebox.rb#L68-L73)
- [`lib/onebox/open_graph.rb:27-47`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/open_graph.rb#L27-L47)
- [`lib/onebox/normalizer.rb:7-41`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/normalizer.rb#L7-L41)
- [`spec/fixtures/onebox/threadsstatus_without_image.response:1`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/spec/fixtures/onebox/threadsstatus_without_image.response#L1)
- [`lib/onebox/sanitize_config.rb:7-13`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/sanitize_config.rb#L7-L13)
- [`lib/onebox/preview.rb:92-97`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/preview.rb#L92-L97)
- [`lib/oneboxer.rb:577-590`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/oneboxer.rb#L577-L590)
- [`lib/cooked_processor_mixin.rb:13-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/cooked_processor_mixin.rb#L13-L45)
- [`frontend/discourse/app/components/post/cooked-html.gjs:201`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/frontend/discourse/app/components/post/cooked-html.gjs#L201)
- [`lib/content_security_policy/default.rb:8-22`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/content_security_policy/default.rb#L8-L22)

