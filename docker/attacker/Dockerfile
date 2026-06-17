FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=/opt/reuserupture-venv/bin:$PATH
# hashcat needs an OpenCL backend. Kali has no PoCL package, so we use Mesa's
# rusticl ICD, which only exposes its CPU (llvmpipe) device when explicitly
# enabled. This lets the AS-REP crack run on any host without GPU drivers.
ENV RUSTICL_ENABLE=llvmpipe

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        git \
        hashcat \
        impacket-scripts \
        jq \
        krb5-user \
        mesa-opencl-icd \
        ncat \
        net-tools \
        ocl-icd-libopencl1 \
        python3 \
        python3-pip \
        python3-venv \
        tcpdump \
        tmux \
        tshark \
    && rm -rf /var/lib/apt/lists/*

# Install uv (used instead of pip for dependency installation).
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH=/root/.local/bin:$PATH

WORKDIR /opt/reuserupture

COPY tool/requirements.txt /tmp/reuserupture-requirements.txt
RUN python3 -m venv /opt/reuserupture-venv \
    && uv pip install --python /opt/reuserupture-venv/bin/python -r /tmp/reuserupture-requirements.txt \
    && printf '#!/usr/bin/env bash\nexec /opt/reuserupture-venv/bin/python /opt/reuserupture/tool/reuserupture.py "$@"\n' > /usr/local/bin/reuserupture \
    && chmod 0755 /usr/local/bin/reuserupture
