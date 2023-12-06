// Android Specific. Get stacktrace like a Java exception.
function get_android_stacktrace() {
    return Java.use("android.util.Log")
               .getStackTraceString(Java.use("java.lang.Exception")
               .$new())
}

// To place into Frida's native function interceptor.
// ctx (context) here is simply "this" that is provided
// by the interceptor scope. 
function get_native_stacktrace(ctx) {
    return Thread.backtrace(ctx.context, Backtracer.ACCURATE)
                 .map(DebugSymbol.fromAddress)
                 .join("\n\t")
}

// Sample usecases:
Java.perform(function() {
    Java.use("java.lang.String").toString.implementation = function() {
        console.warn("java function called")
        console.log(get_android_stacktrace())
        return this.toString()
    }
})

Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        console.warn("native function called")
        // here "this" is provided by the Frida Interceptor.
        // "this" can also be used to share state between
        // onEnter and onLeave
        console.log(get_native_stacktrace(this))
    },
    onLeave: function(retval) {
        console.warn("leaving native function")
    }
})
