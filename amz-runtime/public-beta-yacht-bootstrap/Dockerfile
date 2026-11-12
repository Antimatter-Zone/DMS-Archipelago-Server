# Protected build must bind this local reference to the exact admitted parent
# image ID in runtime-profile.json. There is no pull/tag/build operation here.
ARG PARENT_NATIVE_IMAGE
FROM ${PARENT_NATIVE_IMAGE}
COPY --chown=0:0 bootstrap/ /opt/amz-ap-bootstrap/
ENTRYPOINT ["/usr/local/bin/node", "/opt/amz-ap-bootstrap/launcher.mjs"]
CMD []
