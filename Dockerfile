FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
COPY app ./app
COPY public ./public
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/.next ./.next
COPY public ./public
RUN mkdir -p /tmp/webvh-poc && chown -R node:node /app /tmp/webvh-poc
USER node
EXPOSE 3000
CMD ["npm", "start"]
