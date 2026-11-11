FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .

# Vite inlines these at build time, so they must be supplied as build args.
ARG VITE_SENTINEL_API=http://localhost:8000
ARG VITE_SENTINEL_KEY=sentinel-dev-key
ENV VITE_SENTINEL_API=$VITE_SENTINEL_API \
    VITE_SENTINEL_KEY=$VITE_SENTINEL_KEY
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
