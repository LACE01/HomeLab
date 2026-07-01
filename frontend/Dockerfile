# ---- build stage ----
FROM node:22-slim AS build
WORKDIR /app

COPY package.json yarn.lock* package-lock.json* ./

# react-scripts 5's dependency tree has two known, well-documented conflicts
# with modern npm that this app never pinned a lockfile for:
#   1. react-day-picker@8 doesn't officially list React 19 in its peer range
#      (works fine in practice) -> needs --legacy-peer-deps.
#   2. schema-utils (used by terser-webpack-plugin during the prod build)
#      depends on ajv-keywords@5, which needs ajv@8, but npm's hoisting
#      puts ajv@6 at the root (needed by eslint/fork-ts-checker) -> crashes
#      with "Cannot find module 'ajv/dist/compile/codegen'". Fix: give
#      ajv-keywords its own private ajv@8, without touching the root ajv
#      that eslint and the (unused, no-TypeScript) fork-ts-checker plugin
#      still need at v6.
RUN npm install --legacy-peer-deps --no-audit --no-fund \
 && mkdir -p node_modules/ajv-keywords/node_modules \
 && npm pack ajv@8.17.1 --pack-destination /tmp --silent \
 && tar -xzf /tmp/ajv-8.17.1.tgz -C /tmp \
 && rm -rf node_modules/ajv-keywords/node_modules/ajv \
 && mv /tmp/package node_modules/ajv-keywords/node_modules/ajv \
 && rm -f /tmp/ajv-8.17.1.tgz

COPY . .

# Same-origin deployment: nginx proxies /api to the backend container,
# so the frontend calls relative /api paths and needs no build-time backend URL.
ARG REACT_APP_BACKEND_URL=""
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
ENV ENABLE_HEALTH_CHECK=false

RUN npm run build

# ---- serve stage ----
FROM nginx:1.27-alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
