FROM dsiem-dev/webui-builder AS ui_builder

FROM dsiem-dev/server-builder AS dsiem_builder

FROM dsiem-dev/base-image

ARG S6_OVERLAY_VERSION=3.1.6.2

# s6-overlay using legacy mode
RUN wget https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz -O- | tar -C / -Jxp
RUN wget https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz -O- | tar -C / -Jxp

# fail container if init scripts failed
ENV S6_BEHAVIOUR_IF_STAGE2_FAILS 2
# expose all container env to the target app
ENV S6_KEEP_ENV 1

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
