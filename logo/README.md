# vulnwatch logo

A radar sweep with one blip: the daily scan, and the one finding worth your
attention. All files are plain SVG with the text converted to outlines, so no
font is needed.

## Files

| File | Use |
|---|---|
| `logo-dark.svg` | logo for dark backgrounds (primary) |
| `logo-light.svg` | logo for light backgrounds |
| `logo-mono.svg` / `logo-mono-white.svg` | one color: docs, print, stamps |
| `mark-dark.svg` / `mark-light.svg` | mark only, transparent background |
| `mark-mono.svg` / `mark-mono-white.svg` | mark only, one color |
| `icon.svg` / `icon-light.svg` | app icon / avatar, 128 px tile (Slack bot, GitHub org/repo avatar) |
| `icon-32.svg` | simplified icon for 24–48 px |
| `favicon.svg` | simplified icon for 16 px (HTML report favicon) |
| `mark-light-512.png` | `mark-light.svg` rendered at 512 px, transparent background |
| `icon-512.png` | `icon.svg` rendered at 512 px: Slack app icon (Slack needs PNG/JPG) |

Below 48 px use `icon-32.svg` or `favicon.svg`. The full mark's inner ring and
sweep turn to mush at small sizes.

## README header (switches with GitHub light/dark theme)

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logo/logo-dark.svg">
  <img alt="vulnwatch" src="logo/logo-light.svg" height="64">
</picture>
```

## Colors

| Name | Hex | Use |
|---|---|---|
| Night | `#0B1410` | dark background, text on light |
| Phosphor | `#5BE38A` | mark on dark |
| Blip | `#FFB547` | the finding, on dark |
| Mist | `#DFF5E6` | wordmark on dark |
| Phosphor ink | `#138A4A` | mark on light |
| Blip ink | `#E08A00` | the finding, on light |

Typeface: Space Grotesk Bold (SIL Open Font License), letter-spacing −1.5 px at 42 px.

## Rules

- Keep clear space around the logo of at least the blip's diameter × 2.
- Don't recolor the blip green or the ring amber; the amber dot is the only accent.
- Use the light versions on white and the dark versions on dark. The bright
  phosphor green fails contrast on white.
