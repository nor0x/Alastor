#!/usr/bin/env sh
# Renders the PNG and ICO exports from the SVG sources in art/svg. Needs ImageMagick 7 (magick) with librsvg.
set -eu
cd "$(dirname "$0")"
mkdir -p png ico

render() { # <svg> <size> <out.png>
  magick -background none -density 1200 "svg/$1" -resize "$2x$2" -depth 8 "PNG32:$3"
}

for variant in logo logo-ink logo-white logo-icon; do
  for size in 16 32 48 64 128 256 512 1024; do
    render "$variant.svg" "$size" "png/$variant-$size.png"
  done
done

# Touch icons and PWA/manifest sizes for the app icon.
for size in 180 192; do
  render logo-icon.svg "$size" "png/logo-icon-$size.png"
done

magick png/logo-16.png png/logo-32.png png/logo-48.png png/logo-64.png png/logo-128.png png/logo-256.png ico/logo.ico
magick png/logo-icon-16.png png/logo-icon-32.png png/logo-icon-48.png png/logo-icon-64.png png/logo-icon-128.png png/logo-icon-256.png ico/logo-icon.ico
