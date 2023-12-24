function hook_jni_native_function_register() {
    let addrRegisterNatives = null

    Process.enumerateModules().forEach(function (m) { 
        Module.enumerateSymbolsSync(m.name).forEach(function (s) { 
            if (s.name.includes("RegisterNatives") && (!s.name.includes("CheckJNI"))) {
                addrRegisterNatives = s.address
            }
        })
    })

    if (addrRegisterNatives == null) {
        console.error("Wasn't able to find JNI RegisterNatives")
        return
    }

    Interceptor.attach(addrRegisterNatives, {
        // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
        onEnter: function (args) {
            var nMethods = parseInt(args[3]);
            console.log("\nnMethods="+nMethods);
            
            var class_name = Java.vm.tryGetEnv().getClassName(args[1]);
            console.log("clazz.name="+class_name)
            
            var methods_ptr = ptr(args[2]);
            
            for (var i = 0; i < nMethods; i++) {
                var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize*3));
                var methodName = Memory.readCString(name_ptr);
                var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize*3 + Process.pointerSize));
                var sig = Memory.readCString(sig_ptr);

                console.log("\t"+methodName+"(), sig:", sig)

                var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize*3 + Process.pointerSize*2));

                console.log("\t" + fnPtr_ptr)
            }
        }
    })
}
