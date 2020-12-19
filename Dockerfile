FROM ubuntu:20.04

RUN apt-get update && \
	apt-get install -y build-essential libssl-dev bash openssl

EXPOSE 8080

WORKDIR /encrypted-messaging-system
COPY . .

RUN make install DEST=tree

WORKDIR /encrypted-messaging-system/tree/server-dir

CMD ["./bin/server"]

