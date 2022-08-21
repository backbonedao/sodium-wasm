# Installation

1. Install Emscripten (https://emscripten.org/docs/getting_started/downloads.html)
2. Run `npx pnpm i` to install deps
2. Run `npm run fetch-libsodium` to
3. Make sure `/libsodium` is a symlink to `/deps/libsodium-X.X.X`
4. Run `npm run prebuild && npm run build`
5. Run `sh wasm-build.sh`