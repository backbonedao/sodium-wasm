export LIBSODIUM_FULL_BUILD=1
export NDK_PLATFORM="android-21"

cd libsodium

git clean -xdff

./autogen.sh

./dist-build/android-armv7-a.sh
./dist-build/android-armv8-a.sh
./dist-build/android-x86.sh
./dist-build/android-x86_64.sh

cd ..
mkdir -p native
rm -rf native/*

mv libsodium/libsodium-android-armv7-a deps/armeabi-v7a
mv libsodium/libsodium-android-armv8-a deps/arm64-v8a
mv libsodium/libsodium-android-i686 deps/x86
mv libsodium/libsodium-android-westmere deps/x86_64

cd libsodium
git clean -xdff
cd ..
