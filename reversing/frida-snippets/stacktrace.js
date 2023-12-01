// Native function hook
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                              .map(DebugSymbol.fromAddress)
                              .join("\n\t");
        console.log(backtrace)
    }
})

// Java function hook
function get_stacktrace() {
    console.log(Java.use("android.util.Log")
                    .getStackTraceString(Java.use("java.lang.Exception")
                    .$new()))
}
