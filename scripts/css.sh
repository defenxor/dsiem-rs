#!/bin/sh

for cmd in npx npm; do
  command -v $cmd >/dev/null 2>&1 || {
    echo ${cmd} command doesnt exist
    exit 1
  }
done

root=$(git rev-parse --show-toplevel)
cd $root/web

[ "$1" = "" ] && echo use "prod" or "dev" as 1st argument && exit 1

npm init -y && npm install -y text-spinners@1.0.5 || {
  echo "fails to install text-spinners"
  exit 1
}

npm install -D tailwindcss @tailwindcss/cli || {
  echo "fails to install tailwindcss"
  exit 1
}

echo building tailwind css...
[ "$1" = "prod" ] && NODE_ENV=production npx -y tailwindcss -c ./tailwind.config.js -o ./tailwind.css --minify && exit
[ "$1" = "dev" ] && echo "\nrunning tailwind in watch mode:" && npx tailwindcss -o ./tailwind.css --watch
