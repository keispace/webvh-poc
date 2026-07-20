FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3010
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY public ./public
RUN mkdir -p /app/.data && chown -R node:node /app
USER node
EXPOSE 3010
CMD ["node", "dist/server.js"]
