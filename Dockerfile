FROM rust:latest AS builder

RUN apt-get update 
RUN apt-get install -y build-essential libssl-dev libsqlite3-dev git nettle-dev llvm libclang-dev
RUN rm -rf /var/lib/apt/lists/*
RUN git config --global net.git-fetch-with-cli true

WORKDIR /usr/src/w3registrar
COPY . .
RUN cargo install --path ./

FROM rust:latest
RUN addgroup w3r
RUN adduser --no-create-home --ingroup w3r w3r
RUN mkdir -p /etc/w3registrar
RUN chown -R w3r:w3r /etc/w3registrar

COPY --from=builder /usr/local/cargo/bin/w3registrar /usr/bin/
USER w3r
WORKDIR /etc/w3registrar
CMD ["w3registrar"]
