# The asm-quic node of transport-interop: build/linux-<ISA>/node, a static
# binary. Build with --platform for x86-64; for RISC-V, set QEMU to
# qemu-riscv64 and the node runs under QEMU user mode.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG QEMU=""
RUN if [ -n "$QEMU" ]; then \
        apt-get update && apt-get install -y --no-install-recommends qemu-user && rm -rf /var/lib/apt/lists/*; \
    fi
COPY node /usr/local/bin/asm-quic-node
ENV QEMU=$QEMU
ENTRYPOINT ["/bin/sh", "-c", "exec $QEMU /usr/local/bin/asm-quic-node"]
