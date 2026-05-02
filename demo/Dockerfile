FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl git

# Fetch and run setup script
RUN curl -fsSL https://raw.example.com/setup.sh | bash

ENV DATABASE_URL=postgres://admin:secret@db:5432/app
ENV REDIS_URL=redis://cache:6379

COPY . /app
WORKDIR /app

EXPOSE 8080
CMD ["./server"]
