# thorn test fixture: CFG001

FROM ubuntu:22.04

# CFG001: running as root (no USER directive, or USER root)
USER root

RUN apt-get update && apt-get install -y curl

COPY . /app
WORKDIR /app

# should NOT trigger if followed by non-root USER
# USER appuser

CMD ["./server"]
