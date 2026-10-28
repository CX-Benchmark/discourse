# OpenGraph title_attr interpolates third-party media titles unescaped into host-specific onebox HTML

| Field | Value |
|---|---|
| ID | `find_016XAd1f9eNSoCqCm7QG7mvi` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-79 — HTML injection |
| Created | 2026-10-27T21:27:09.230662Z |
| Claude Security | https://claude.ai/security/findings/find_016XAd1f9eNSoCqCm7QG7mvi |

## Description

A registered user who can post a link can inject their own `style` attributes and `<style>` elements into a post. Every reader of the topic gets them. This allows a clickable full-page overlay, hidden or restyled interface and moderation controls, and tracking beacons. Script execution stays blocked. The cause is `Onebox::OpenGraph#title_attr` and the onebox engines that put third-party media titles into HTML without escaping them.

```mermaid
flowchart TD
  n1["post author (TL0 user)"]
  n2["media title on Imgur, Giphy, Flickr and similar"]
  n3["title_attr and the onebox engines that interpolate it"]
  n4["Preview sanitize with DISCOURSE_ONEBOX"]
  n5["post.cooked shown to all readers"]
  n6["HTML escaping of the title at output"]
  n1 -->|"sets title with an apostrophe and style"| n2
  n2 -->|"title fetched by onebox"| n3
  n3 -->|"emits tag with injected attributes"| n4
  n4 -->|"keeps style and style elements"| n5
  n6 -->|"not applied"| n3
  classDef actor stroke:#2563eb,stroke-width:2px
  classDef vulnerable_code stroke:#dc2626,stroke-width:2px
  classDef existing_control stroke:#16a34a,stroke-width:2px
  classDef missing_control stroke:#dc2626,stroke-width:2px,stroke-dasharray:5 5
  classDef asset stroke:#9333ea,stroke-width:2px
  classDef component stroke:#6b7280,stroke-width:1px
  class n1 actor
  class n2 component
  class n3 vulnerable_code
  class n4 existing_control
  class n5 asset
  class n6 missing_control
```

1. **attacker** sets the title of their own media item on a supported platform. The title holds an apostrophe followed by extra attributes, for example `a' style='position:fixed;top:0;left:0;width:100%;height:100%;z-index:999`, and the platforms keep `'` and `&` in user titles. ([`spec/fixtures/onebox/imgur.response:66`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/spec/fixtures/onebox/imgur.response#L66))
2. **attacker** posts that media URL on its own line in a Discourse post. `CookedPostProcessor` calls `Oneboxer.onebox`, and the engine reads the title from `og:title` or the oEmbed data. The normalizer decodes entities after sanitizing and cuts the title to 80 characters. ([`lib/onebox/normalizer.rb:35-41`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/normalizer.rb#L35-L41))
3. **`title_attr` in `Onebox::OpenGraph`** returns the title inside single quotes with no HTML escaping. It builds `title='...'` from the raw title, so one apostrophe in the title ends the attribute. `Onebox::Oembed` inherits the method, so oEmbed titles reach it too. ([`lib/onebox/open_graph.rb:13-15`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/open_graph.rb#L13-L15))
4. **the engine `ImgurOnebox`** splices `og.title_attr` into an `<img>` tag by string interpolation. The attacker's extra attributes become real attributes of the tag. `AnimatedImageOnebox`, `FlickrOnebox`, `FiveHundredPxOnebox` and `GooglePhotosOnebox` do the same. ([`lib/onebox/engine/imgur_onebox.rb:61-69`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/imgur_onebox.rb#L61-L69))
5. **`Onebox::Preview#sanitize`** runs the HTML through `SanitizeConfig::DISCOURSE_ONEBOX` and keeps the injected parts. This config is Sanitize `RELAXED` plus extras. It allows `style`, `class` and `id` on every element and allows `<style>` elements. ([`lib/onebox/sanitize_config.rb:7-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/sanitize_config.rb#L7-L45))
6. **`CookedProcessorMixin#post_process_oneboxes`** stores the sanitized onebox HTML in `post.cooked`. No later step removes `style` attributes or `<style>` elements, so they apply for everyone who opens the topic. ([`lib/cooked_processor_mixin.rb:13-47`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/cooked_processor_mixin.rb#L13-L47))

## Assessment

The attacker is a registered Discourse user who can post a link (TL0). They set the title of their own Imgur post, or a Giphy, Flickr or 500px upload, to a value with an apostrophe followed by attributes. They then post that media URL on its own line. Other affected engines are `FlickrShortenedOnebox`, `GooglePhotosOnebox` and `CloudAppOnebox`. The `placeholder_html` of BandCamp, SoundCloud, Coub, Wistia, Simplecast, Audioboom, audio.com and Replit does the same. A second route is a title that the platform encoded once, such as `&amp;lt;`. The normalizer decodes it after sanitizing, so it becomes a literal `<`, and a payload like `'><style>…</style><img title='` can add whole elements. Imgur's fixture shows a title with `<b>` encoded once in this way. The report assumes Sanitize 7.0.0 `RELAXED` allows `style` with properties such as `position`, `top`, `left`, `width`, `height` and `z-index`, and allows the `style` element.

Impact: The attacker stores HTML and CSS in posts that post authors cannot otherwise produce. They can cover the page with a clickable overlay (the Imgur image sits inside a link), hide or restyle UI and moderation controls, and deface or blank the topic for all readers. An injected `<style>` element can add selector-based `url()` beacons that leak limited facts about the viewer. The CSP `script-src` and Sanitize block script, so the impact stays limited.

## Recommendation

(1) `OpenGraph#title_attr` and the engines that interpolate `og.title` or `oembed.title` build HTML attributes and text by string interpolation without escaping. A remote title can therefore break out of the `title='…'` attribute.

Fix criteria: Every remote title placed in onebox HTML is HTML-escaped for its context, quotes included, or is emitted through Mustache `{{ }}`. A giphy, Imgur or Flickr page whose `og:title` is `a' style='position:fixed` yields one `<img>`. Its `title` attribute holds that literal text and it has no `style` attribute.

(2) `Normalizer#sanitize_value` entity-decodes after `Sanitize.fragment`. This re-creates the `<` and `>` that the sanitizer had encoded, so values described as sanitized can carry markup.

Fix criteria: Normalized values contain no markup characters re-introduced after sanitization, or every consumer treats them as plain text and escapes them. An `og:title` whose page source is `&amp;amp;lt;style&amp;amp;gt;` yields no literal `<style>` in any onebox output.

## Evidence

**https://github.com/cx-benchmark/discourse**

- [`lib/onebox/open_graph.rb:13-15`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/open_graph.rb#L13-L15)
- [`lib/onebox/normalizer.rb:35-41`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/normalizer.rb#L35-L41)
- [`lib/onebox/engine/imgur_onebox.rb:61-69`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/imgur_onebox.rb#L61-L69)
- [`lib/onebox/engine/animated_image_onebox.rb:12-20`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/animated_image_onebox.rb#L12-L20)
- [`lib/onebox/engine/flickr_onebox.rb:27-53`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/flickr_onebox.rb#L27-L53)
- [`lib/onebox/engine/five_hundred_px_onebox.rb:16-19`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/five_hundred_px_onebox.rb#L16-L19)
- [`lib/onebox/engine/google_photos_onebox.rb:48-74`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/engine/google_photos_onebox.rb#L48-L74)
- [`lib/onebox/preview.rb:210-215`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/preview.rb#L210-L215)
- [`lib/oneboxer.rb:578-592`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/oneboxer.rb#L578-L592)
- [`lib/onebox/sanitize_config.rb:7-45`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/onebox/sanitize_config.rb#L7-L45)
- [`lib/cooked_processor_mixin.rb:13-47`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/lib/cooked_processor_mixin.rb#L13-L47)
- [`spec/fixtures/onebox/imgur.response:66`](https://github.com/cx-benchmark/discourse/blob/e08ed05b4b1ef773b2de7948a8f88a7c182a3520/spec/fixtures/onebox/imgur.response#L66)

