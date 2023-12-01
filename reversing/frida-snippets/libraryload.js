// Native libs
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        console.warn("dlopen: " + Memory.readCString(args[0]))
    }
})

// System.loadLibrary hook
// For some reason, calling Java.use("java.lang.System").loadLibrary("lib")
// doesn't work and we need this workaround. 
Java.use("java.lang.System").loadLibrary.implementation = function (lib) {
    console.warn("System.loadLibrary: " + lib.toString())
    Java.use("java.lang.Runtime").getRuntime().loadLibrary0(Java.use('dalvik.system.VMStack').getCallingClassLoader(), lib);
}
