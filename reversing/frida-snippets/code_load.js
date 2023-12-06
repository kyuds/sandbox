// Native libs
function dlopen_load() {
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            console.warn("dlopen: " + Memory.readCString(args[0]))
        }
    })
}

// System.loadLibrary hook
// For some reason, calling Java.use("java.lang.System").loadLibrary("lib")
// doesn't work and we need this workaround. 
function java_load() {
    Java.use("java.lang.System").loadLibrary.implementation = function(lib) {
        console.warn("System.loadLibrary: " + lib.toString())
        Java.use("java.lang.Runtime").getRuntime().loadLibrary0(Java.use('dalvik.system.VMStack').getCallingClassLoader(), lib);
    }
}

// There are multiple options on dynamically loading DEX files into android. 
function dex_loads() {
    const DC = Java.use("dalvik.system.DexClassLoader")
    const PC = Java.use("dalvik.system.PathClassLoader")
    const IC = Java.use("dalvik.system.InMemoryDexClassLoader")

    DC.$init.implementation = function(a0, a1, a2, a3) {
        console.error("DC: loading something")
        console.log("dex path: " + a0)
        console.log("library search path: " + a2)
        return this.$init(a0, a1, a2, a3)
    }
    PC.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(a0, a1) {
        console.error("PC<2>: loading something")
        console.log("dex path: " + a0)
        return this.$init(a0, a1)
    }
    PC.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(a0, a1, a2) {
        console.error("PC<3>: loading something")
        console.log("dex path: " + a0)
        return this.$init(a0, a1, a2)
    }
    IC.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(a0, a1) {
        console.error("IC<2-1>: loading something")
        return this.$init(a0, a1)
    }
    IC.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader').implementation = function(a0, a1) {
        console.error("IC<2-2>: loading something")
        return this.$init(a0, a1)
    }
}
