# UI build stage
#
# IMPORTANT: This Dockerfile expects the *build context* to be a directory that
# contains BOTH:
#   - ospmae/
#   - mosp-design-system/
# (i.e. siblings).
#
# Example:
#   /workspace/
#     ospmae/
#     mosp-design-system/
#
# Build with:
#   docker build -f ospmae/services/ui/Dockerfile -t ospmae-ui /workspace

FROM node:20-alpine AS ui-assets
WORKDIR /ui

COPY ospmae/services/ui/package.json ospmae/services/ui/package-lock.json* ./
COPY ospmae/services/ui/scripts ./scripts
RUN npm install

# Inject MOSP design system (local codebase, no npm registry)
COPY mosp-design-system/ /tmp/mosp-design-system/
RUN (cd /tmp/mosp-design-system && node scripts/build.mjs) \
 && mkdir -p /ui/node_modules/@FERCBusters \
 && rm -rf /ui/node_modules/@FERCBusters/mosp-design-system \
 && cp -a /tmp/mosp-design-system /ui/node_modules/@FERCBusters/mosp-design-system \
 && rm -rf /ui/node_modules/@FERCBusters/mosp-design-system/node_modules

COPY ospmae/services/ui/public ./public
RUN npm run vendor-assets

FROM nginx:1.30.4-alpine

COPY ospmae/services/ui/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY ospmae/services/ui/public /usr/share/nginx/html
COPY --from=ui-assets /ui/public/vendor /usr/share/nginx/html/vendor
