# NOT BUILT OR TESTED in the authoring environment. Base image referenced by tag, not digest: pin before relying on it.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY . /work
RUN cd codemode && npm ci
CMD ["sh", "scripts/repro_p9.sh"]
