FROM ubuntu:22.04
RUN curl -fsSL https://get.docker.com | bash
RUN apt-get install -y curl
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
