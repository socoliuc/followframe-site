FROM node:26-alpine

WORKDIR /app
COPY public /app/public
COPY production-server.ts metrics.ts /app/

ENV PORT=80
ENV STATIC_ROOT=/app/public
ENV METRICS_DB_PATH=/app/data/followframe-metrics.sqlite
EXPOSE 80
VOLUME ["/app/data"]

CMD ["node", "production-server.ts"]
