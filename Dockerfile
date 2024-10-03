FROM node:18.19.0

# Install libvips and other dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libvips-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
COPY yarn.lock ./

RUN mkdir /app/libs
COPY libs/* /app/libs

#RUN npm install

RUN yarn
COPY . .

EXPOSE ${PORT}

COPY entrypoint.sh /

COPY src/seed/paymentMethod.json /
COPY src/seed/categoryDefault.json /

RUN chmod +x entrypoint.sh
VOLUME ["/app/uploads"]

CMD ["./entrypoint.sh"]


