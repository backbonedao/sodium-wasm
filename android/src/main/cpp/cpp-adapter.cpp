#include <jni.h>
#include <jsi/jsi.h>
#include "SodiumHostObject.h"

using namespace facebook::jsi;
using namespace std;

void install(Runtime& runtime) {
    auto hostObject = make_shared<screamingvoid::SodiumHostObject>();
    auto object = Object::createFromHostObject(runtime, hostObject);
    runtime.global().setProperty(runtime, "__SodiumProxy", move(object));
}

extern "C"
JNIEXPORT void JNICALL
Java_me_screamingvoid_sodiumuniversal_SodiumModule_nativeInstall(JNIEnv *env, jclass clazz, jlong jsiPtr) {
    auto runtime = reinterpret_cast<Runtime*>(jsiPtr);
    if (runtime) {
        install(*runtime);
    }
    // if runtime was nullptr, Sodium will not be installed. This should only happen while Remote Debugging (Chrome), but will be weird either way.
}
