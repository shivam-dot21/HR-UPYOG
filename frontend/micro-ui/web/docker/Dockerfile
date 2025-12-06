FROM upyogio/alpine-node-builder-14:yarn AS build
#FROM ghcr.io/egovernments/alpine-node-builder-14:yarn AS build
RUN apk update && apk upgrade
RUN apk add --no-cache git>2.30.0
RUN yarn add @upyog/digit-ui-libraries@3.0.0
RUN yarn add @upyog/digit-ui-module-mcollect@3.0.2
RUN yarn add @upyog/digit-ui-module-pgr@3.0.0
RUN yarn add @upyog/digit-ui-module-hrms@3.0.0
RUN yarn add @upyog/digit-ui-module-core@3.0.5
RUN yarn add @upyog/digit-ui-module-common@3.0.4
RUN yarn add @upyog/digit-ui-module-bills@3.0.0
RUN yarn add @nudmcdgnpm/digit-ui-react-components@1.2.6

ARG WORK_DIR
WORKDIR /app
ENV NODE_OPTIONS "--max-old-space-size=12288"
ENV GENERATE_SOURCEMAP "false"

COPY ${WORK_DIR} .
RUN ls -lah

#RUN node web/envs.js
RUN cd web/ \
    && node envs.js \
    && node -e 'console.log(v8.getHeapStatistics().heap_size_limit/(12288*12288))' \
    &&  ./install-deps.sh \
    && yarn install \
    && yarn build 
    

FROM nginx:mainline-alpine
#FROM ghcr.io/egovernments/nginx:mainline-alpine
ENV WORK_DIR=/var/web/digit-ui

RUN mkdir -p ${WORK_DIR}

COPY --from=build /app/web/build ${WORK_DIR}/
COPY --from=build /app/web/docker/nginx.conf /etc/nginx/conf.d/default.conf