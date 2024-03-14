FROM node:current-slim as css_builder
WORKDIR /
COPY ./ctx/web ./web
WORKDIR /web
ENV NODE_ENV=production
RUN npx -y tailwindcss -c ./tailwind.config.js -o ./tailwind.css --minify
RUN npm init -y && npm install -y text-spinners@1.0.5

FROM rust AS ui_builder
WORKDIR /

# just for the workspace manifests
COPY ./ctx/Cargo.toml ./
RUN cargo init server

COPY ./ctx/web ./web
WORKDIR /web
COPY --from=css_builder /web/tailwind.css ./
COPY --from=css_builder /web/node_modules ./node_modules
RUN apt-get update && apt-get install -y wget
ADD https://github.com/trunk-rs/trunk/releases/download/v0.19.0/trunk-x86_64-unknown-linux-gnu.tar.gz /tmp/
RUN tar -xzf /tmp/trunk-x86_64-unknown-linux-gnu.tar.gz -C /usr/local/bin
RUN rustup target add wasm32-unknown-unknown
RUN trunk build --public-url /ui --release index.html

FROM rust AS dsiem_builder
COPY . .
WORKDIR /ctx
RUN cd server && cargo fetch
RUN cargo build -p dsiem --release

FROM mmta/alpine-glibc AS base

ARG S6_OVERLAY_VERSION=3.1.6.2

# s6-overlay using legacy mode
RUN wget https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz -O- | tar -C / -Jxp
RUN wget https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz -O- | tar -C / -Jxp

# fail container if init scripts failed
ENV S6_BEHAVIOUR_IF_STAGE2_FAILS 2
# expose all container env to the target app
ENV S6_KEEP_ENV 1

FROM base AS final
WORKDIR /dsiem

# create dirs for configs and web/dist/assets/config, the later is accessed by UI to load esconfig.json
RUN mkdir -p configs web/dist/assets/config

# copy s6files
ADD s6files /etc/
RUN chmod +x /etc/services.d/*/run

COPY --from=dsiem_builder /ctx/target/release/dsiem-backend ./
COPY --from=dsiem_builder /ctx/target/release/dsiem-frontend ./
COPY --from=ui_builder /web/dist ./web/dist

# copy default configs to config-dist. /dsiem/configs will be repopulated with those default files on
# frontend start if no configs are present
COPY ./ctx/configs ./configs-dist

VOLUME [ "/dsiem/logs", "/dsiem/configs" ]
ENTRYPOINT [ "/init" ]
