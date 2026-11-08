FROM node:24.20.0-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e AS node
FROM python:3.12-slim-bookworm@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 SKIP_REQUIREMENTS_UPDATE=1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/x86_64-linux-gnu/libstdc++.so.6
COPY --from=node /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=node /usr/lib/x86_64-linux-gnu/libatomic.so.1 /usr/lib/x86_64-linux-gnu/libatomic.so.1
COPY --from=node /usr/local/LICENSE /licenses/Node-LICENSE
COPY wheels/ /wheels/
COPY requirements.lock /requirements.lock
RUN --network=none python -m pip install --no-cache-dir --no-index --find-links=/wheels --require-hashes --no-deps -r /requirements.lock \
 && python -m pip check && rm -rf /wheels
COPY engine/ /engine/
COPY runtime/ /opt/amz-ap/
COPY dependencies.v1.json source-provenance.v1.json server-runtime.v1.json /opt/amz-ap/
WORKDIR /home/container
USER 65532:65532
ENTRYPOINT ["node","/opt/amz-ap/launcher.mjs"]
