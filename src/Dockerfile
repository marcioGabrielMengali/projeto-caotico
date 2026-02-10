FROM node:18-alpine3.19
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 8080
USER marcio
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "executable" ]
CMD ["node", "server.js"]
