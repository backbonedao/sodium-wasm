"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "Sodium", {
    enumerable: true,
    get: ()=>Sodium
});
const _reactNative = require("react-native");
// Check if the constructor exists. If not, try installing the JSI bindings.
if (global.__SodiumProxy == null) {
    // Get the native Sodium ReactModule
    const SodiumModule = _reactNative.NativeModules.Sodium;
    if (SodiumModule == null) {
        var ref, ref1;
        let message = "Failed to install sodium-universal: The native `Sodium` Module could not be found.";
        message += "\n* Make sure sodium-universal is correctly autolinked (run `npx react-native config` to verify)";
        if (_reactNative.Platform.OS === "ios" || _reactNative.Platform.OS === "macos") {
            message += "\n* Make sure you ran `pod install` in the ios/ directory.";
        }
        if (_reactNative.Platform.OS === "android") {
            message += "\n* Make sure gradle is synced.";
        }
        // check if Expo
        const ExpoConstants = (ref = _reactNative.NativeModules.NativeUnimoduleProxy) === null || ref === void 0 ? void 0 : (ref1 = ref.modulesConstants) === null || ref1 === void 0 ? void 0 : ref1.ExponentConstants;
        if (ExpoConstants != null) {
            if (ExpoConstants.appOwnership === "expo") {
                // We're running Expo Go
                throw new Error("sodium-universal is not supported in Expo Go! Use EAS (`expo prebuild`) or eject to a bare workflow instead.");
            } else {
                // We're running Expo bare / standalone
                message += "\n* Make sure you ran `expo prebuild`.";
            }
        }
        message += "\n* Make sure you rebuilt the app.";
        throw new Error(message);
    }
    // Check if we are running on-device (JSI)
    if (global.nativeCallSyncHook == null || SodiumModule.install == null) {
        throw new Error("Failed to install sodium-universal: React Native is not running on-device. Sodium can only be used when synchronous method invocations (JSI) are possible. If you are using a remote debugger (e.g. Chrome), switch to an on-device debugger (e.g. Flipper) instead.");
    }
    // Call the synchronous blocking install() function
    const result = SodiumModule.install();
    if (result !== true) throw new Error(`Failed to install sodium-universal: The native Sodium Module could not be installed! Looks like something went wrong when installing JSI bindings: ${result}`);
    // Check again if the constructor now exists. If not, throw an error.
    if (global.__SodiumProxy == null) throw new Error("Failed to install sodium-universal, the native initializer function does not exist. Are you trying to use Sodium from different JS Runtimes?");
}
const Sodium = global.__SodiumProxy;
