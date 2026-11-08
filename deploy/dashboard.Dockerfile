FROM docker.io/library/node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY sdk/typescript/package.json sdk/typescript/
COPY apps/dashboard/package.json apps/dashboard/
COPY apps/shopping-agent/package.json apps/shopping-agent/
RUN npm ci
COPY sdk/typescript sdk/typescript
COPY apps/dashboard apps/dashboard
RUN npm run build -w apps/dashboard

FROM docker.io/library/nginx:1.27-alpine
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/apps/dashboard/dist /usr/share/nginx/html
