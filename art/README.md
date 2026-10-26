# Art

The Alastor mark: a ring on a broken diagonal, with a watching pupil. The source of truth is
`src/alastor-web/src/lib/ui/Logo.svelte`; these files are static exports of it.

| Variant      | Use                                         | Colors                      |
|--------------|---------------------------------------------|-----------------------------|
| `logo`       | Default, works on light and dark backgrounds | accent `#0462d3`            |
| `logo-ink`   | Monochrome on light backgrounds             | ink `#111825`               |
| `logo-white` | Monochrome on dark or photo backgrounds     | white `#ffffff`             |
| `logo-icon`  | App icon, avatar, favicon, social preview   | paper `#f8fbfe` on accent   |

- `svg/`: the vector sources, one per variant.
- `png/`: every variant at 16, 32, 48, 64, 128, 256, 512 and 1024 px, plus `logo-icon` at 180 (Apple touch icon) and
  192 (web manifest).
- `ico/`: multi-size Windows/favicon icons (16 to 256 px) for `logo` and `logo-icon`.

Edit the SVGs, then regenerate the PNG and ICO files with `sh art/render.sh` (needs ImageMagick 7 with librsvg).
