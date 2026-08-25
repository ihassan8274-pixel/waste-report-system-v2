FROM node:24-slim

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js database.js ./
COPY public ./public

ENV NODE_ENV=production
ENV DATA_DIR=/app/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
