use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jstring;

/// Proves the Rust -> JNI -> Kotlin wiring works end to end.
/// The session/streaming/input API surface is ported on top of this next.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match env.new_string(env!("CARGO_PKG_VERSION")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
