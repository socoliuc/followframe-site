FROM node:26-alpine

WORKDIR /app
COPY index.html /app/public/index.html
COPY assets /app/public/assets
COPY downloads /app/public/downloads
COPY screenshots /app/public/screenshots
COPY og /app/public/og
COPY privacy /app/public/privacy
COPY app-icon-128.webp app-icon.png favicon.svg google9b59e4c5f5a8c8b0.html robots.txt sitemap.xml site.webmanifest /app/public/
COPY production-server.ts /app/production-server.ts

ENV PORT=80
ENV STATIC_ROOT=/app/public
EXPOSE 80

CMD ["node", "production-server.ts"]
