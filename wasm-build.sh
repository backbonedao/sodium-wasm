export MAKE_FLAGS="-j4"
export LDFLAGS="-s RESERVED_FUNCTION_POINTERS=8"
export LDFLAGS="${LDFLAGS} -s ASSERTIONS=0"
export LDFLAGS="${LDFLAGS} -s ALLOW_MEMORY_GROWTH=1"
export LDFLAGS="${LDFLAGS} -s AGGRESSIVE_VARIABLE_ELIMINATION=1 -s ALIASING_FUNCTION_POINTERS=1"
export LDFLAGS="${LDFLAGS} -s DISABLE_EXCEPTION_CATCHING=1"
export LDFLAGS="${LDFLAGS} -s ELIMINATE_DUPLICATE_FUNCTIONS=1"

cd libsodium
#git clean -xdff
./autogen.sh
emconfigure ./configure \
  --disable-shared \
  --prefix="$(pwd)/libsodium-js" \
  --without-pthreads \
  --disable-ssp \
  --disable-asm \
  --disable-pie \
  CFLAGS="--no-entry -Oz -s STANDALONE_WASM -s WASM_BIGINT -DNDEBUG -UHAVE_MEMSET_S" && \
  emmake make clean

emmake make $MAKE_FLAGS install
cd ..

mkdir -p deps/wasm32

emcc \
  --no-entry \
  -Oz \
  -Ilibsodium/libsodium-js/include \
  -DNDEBUG \
  -UHAVE_MEMSET_S \
  -s STANDALONE_WASM \
  -s WASM_BIGINT \
  ${LDFLAGS} \
  -s EXPORTED_FUNCTIONS=@./functions.txt \
  -o "deps/wasm32/libsodium.wasm" \
  libsodium/libsodium-js/lib/libsodium.a

echo "export const WASM = \`$(base64 deps/wasm32/libsodium.wasm)\`;" > src/wasm.ts

cd libsodium
#git clean -xdff
cd ..
