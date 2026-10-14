#!/bin/sh
# Mutolaxona saytini Netlify'ga joylash. Node.js o'rnatilgan bo'lishi kerak: https://nodejs.org
cd "$(dirname "$0")" || exit 1
npm install && npx --yes netlify-cli deploy --prod
