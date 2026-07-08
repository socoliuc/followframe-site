FROM nginx:1.27-alpine

COPY index.html /usr/share/nginx/html/index.html
COPY assets /usr/share/nginx/html/assets
COPY downloads /usr/share/nginx/html/downloads
COPY screenshots /usr/share/nginx/html/screenshots
COPY og /usr/share/nginx/html/og
COPY favicon.svg robots.txt sitemap.xml site.webmanifest /usr/share/nginx/html/
