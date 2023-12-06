// Android only!
function print_pid() {
    console.log(Java.use("android.os.Process").myPid())
}
