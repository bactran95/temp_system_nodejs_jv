#!/bin/sh

yarn
# echo "====== run migrate ======"
# npm run migration:create name-file
# npm run migration:run

yarn build

cp /paymentMethod.json /app/dist/src/seed/paymentMethod.json
cp /paymentMethod.json /app/dist/src/seed/categoryDefault.json

yarn add sharp --ignore-engines

node -r ./tsconfig-paths-bootstrap.js dist/index.js

