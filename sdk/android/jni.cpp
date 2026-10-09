#include "../../src/core-api.h"
#include <jni.h>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>
namespace {
JavaVM* vm=nullptr;std::mutex run_mutex;
struct Attached {
    JNIEnv* env=nullptr;bool detach=false;
    Attached(){if(vm->GetEnv(reinterpret_cast<void**>(&env),JNI_VERSION_1_6)==JNI_EDETACHED){
#ifdef __ANDROID__
        detach=vm->AttachCurrentThread(&env,nullptr)==JNI_OK;
#else
        detach=vm->AttachCurrentThread(reinterpret_cast<void**>(&env),nullptr)==JNI_OK;
#endif
        if(!detach)env=nullptr;}}
    ~Attached(){if(detach)vm->DetachCurrentThread();}
};
struct Hooks {jobject object=nullptr;jmethodID protect=nullptr,resolve=nullptr;};
int protect(int64_t fd,void* user){
    if(fd<0||fd>INT32_MAX)return 0;Attached thread;if(!thread.env)return 0;
    auto& h=*static_cast<Hooks*>(user);auto ok=thread.env->CallBooleanMethod(h.object,h.protect,jint(fd));
    if(thread.env->ExceptionCheck()){thread.env->ExceptionClear();return 0;}return ok==JNI_TRUE?1:0;
}
int resolve(const char* host,char* output,int capacity,void* user){
    Attached thread;if(!thread.env)return -1;auto env=thread.env;auto& h=*static_cast<Hooks*>(user);
    auto name=env->NewStringUTF(host);if(!name){env->ExceptionClear();return -1;}
    auto array=static_cast<jobjectArray>(env->CallObjectMethod(h.object,h.resolve,name));env->DeleteLocalRef(name);
    if(env->ExceptionCheck()){env->ExceptionClear();return -1;}if(!array)return -1;
    auto count=env->GetArrayLength(array);std::string addresses;bool good=count>0&&count<=32;
    for(jsize i=0;good&&i<count;++i){auto item=static_cast<jstring>(env->GetObjectArrayElement(array,i));if(!item){good=false;break;}
        auto text=env->GetStringUTFChars(item,nullptr);if(!text){env->ExceptionClear();env->DeleteLocalRef(item);good=false;break;}
        addresses+=text;addresses+='\n';env->ReleaseStringUTFChars(item,text);env->DeleteLocalRef(item);
        if(addresses.size()>=size_t(capacity))good=false;
    }env->DeleteLocalRef(array);if(!good)return -1;std::memcpy(output,addresses.data(),addresses.size());return int(addresses.size());
}
}
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* machine,void*){vm=machine;return JNI_VERSION_1_6;}
static jint runNative(JNIEnv* env,jbyteArray path,jobject object,jint fd){
    std::unique_lock<std::mutex> lock(run_mutex,std::try_to_lock);if(!lock.owns_lock())return 2;
    if(!path)return 1;auto size=env->GetArrayLength(path);if(size<1||size>32768)return 1;
    std::string file(size_t(size),'\0');env->GetByteArrayRegion(path,0,size,reinterpret_cast<jbyte*>(file.data()));
    if(env->ExceptionCheck()||file.find('\0')!=std::string::npos)return 1;
    Hooks hooks;
    if(object){hooks.object=env->NewGlobalRef(object);auto type=env->GetObjectClass(object);
        hooks.protect=env->GetMethodID(type,"protect","(I)Z");hooks.resolve=env->GetMethodID(type,"resolve","(Ljava/lang/String;)[Ljava/lang/String;");env->DeleteLocalRef(type);
        if(env->ExceptionCheck()||!hooks.object||!hooks.protect||!hooks.resolve){if(hooks.object)env->DeleteGlobalRef(hooks.object);return 1;}}
    vpn_core_tun_options options{};options.size=sizeof(options);options.abi=1;options.fd=fd;options.kind=VPN_CORE_TUN_FD;options.mtu=1500;options.maximum_flows=64;
    int result=fd>=0?vpn_core_run_tun(file.c_str(),&options,object?protect:nullptr,object?resolve:nullptr,&hooks):vpn_core_run_config(file.c_str(),object?protect:nullptr,object?resolve:nullptr,&hooks);
    if(hooks.object)env->DeleteGlobalRef(hooks.object);return result;
}
extern "C" JNIEXPORT jint JNICALL Java_com_noorelmostafa_vpncore_NativeCore_nativeRun(JNIEnv* env,jclass,jbyteArray path,jobject object){return runNative(env,path,object,-1);}
extern "C" JNIEXPORT jint JNICALL Java_com_noorelmostafa_vpncore_NativeCore_nativeRunTun(JNIEnv* env,jclass,jbyteArray path,jint fd,jobject object){if(fd<0||!object)return 1;return runNative(env,path,object,fd);}
extern "C" JNIEXPORT jint JNICALL Java_com_noorelmostafa_vpncore_NativeCore_tunAbiVersion(JNIEnv*,jclass){return vpn_core_tun_abi_version();}
extern "C" JNIEXPORT jboolean JNICALL Java_com_noorelmostafa_vpncore_NativeCore_tunReady(JNIEnv*,jclass){return vpn_core_tun_ready()?JNI_TRUE:JNI_FALSE;}
extern "C" JNIEXPORT void JNICALL Java_com_noorelmostafa_vpncore_NativeCore_stop(JNIEnv*,jclass){vpn_core_stop();}
extern "C" JNIEXPORT jstring JNICALL Java_com_noorelmostafa_vpncore_NativeCore_version(JNIEnv* env,jclass){return env->NewStringUTF(vpn_core_version());}
extern "C" JNIEXPORT jint JNICALL Java_com_noorelmostafa_vpncore_NativeCore_abiVersion(JNIEnv*,jclass){return jint(vpn_core_abi_version());}
extern "C" JNIEXPORT jint JNICALL Java_com_noorelmostafa_vpncore_NativeCore_state(JNIEnv*,jclass){return vpn_core_get_state();}
extern "C" JNIEXPORT jint JNICALL Java_com_noorelmostafa_vpncore_NativeCore_listenPort(JNIEnv*,jclass){return vpn_core_get_listen_port();}

extern "C" JNIEXPORT jstring JNICALL Java_com_noorelmostafa_vpncore_NativeCore_readEvent(JNIEnv* env,jclass){char out[4096];int n=vpn_core_read_event(out,sizeof(out));return n>0?env->NewStringUTF(out):nullptr;}
extern "C" JNIEXPORT jint JNICALL Java_com_noorelmostafa_vpncore_NativeCore_pendingCallbacks(JNIEnv*,jclass){return jint(vpn_core_pending_callbacks());}
