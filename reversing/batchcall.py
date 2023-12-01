# Batch calling to scrape all functions from
# IDA decompiled binaries to sort through
# dead code. 

import frida, time

# Settings #
BATCH = 20
APP_NAME = ""
SUB_NAME = ""
CYCLE_DURATION = 8

def run(verbose=False):
    file1 = open(SUB_NAME, 'r')
    Lines = file1.readlines()
    
    count = 0
    subs = []
    for line in Lines:
        count += 1
        if len(line) == 0 or count <= 2:
            continue
        subs.append(line.split()[0])

    print(len(subs), "sub-functions will be processed")
    print("expected duration:", len(subs) // BATCH * CYCLE_DURATION, "seconds")

    called, cnt = set(), 0

    def on_message(message, data):
        if message["type"] == "send":
            called.add(message["payload"])
        if message["type"] == "error" and verbose:
            print(message)

    while cnt < len(subs):
        test_round = subs[cnt : min(len(subs), cnt + BATCH)]
        js = get_javascript(test_round)

        device = frida.get_usb_device()
        pid = device.spawn([APP_NAME])
        session = device.attach(pid)

        script = session.create_script(js)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(CYCLE_DURATION)
        cnt += BATCH

    print("finished.")

    if verbose:
        print("uncalled sub-function:\n", set(subs) - called)
        
    return set(subs), called

def get_javascript(round):
    return """
let addrRegisterNatives = null
Process.enumerateModules().forEach(function (m) {{
    Module.enumerateSymbolsSync(m.name).forEach(function (s) {{
        if (s.name.includes("RegisterNatives") && (!s.name.includes("CheckJNI"))) {{
            addrRegisterNatives = s.address
        }}
    }})
}})

var offset = <xxxx>
var lib_start = null
Interceptor.attach(addrRegisterNatives, {{
    onEnter: function (args) {{
        var nMethods = parseInt(args[3]);        
        var class_name = Java.vm.tryGetEnv().getClassName(args[1]);
        var methods_ptr = ptr(args[2]);
        
        for (var i = 0; i < nMethods; i++) {{
            var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize*3));
            var methodName = Memory.readCString(name_ptr);
            var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize*3 + Process.pointerSize));
            var sig = Memory.readCString(sig_ptr);
            var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize*3 + Process.pointerSize*2));
            if (methodName == "xxxx" && sig == "([I)V") {{
                lib_start = fnPtr_ptr - offset 
                hook_from_dynamically_loaded()
            }}
        }}
    }}
}})

var subs = {sublist}

function hook_from_dynamically_loaded() {{
    if (lib_start == null) {{
        return
    }}
    function hook_internal(sub_name, sub_ptr) {{
        Interceptor.attach(sub_ptr, {{
            onEnter: function(args) {{
                send(sub_name)
            }}
        }})
    }}

    for(var i = 0; i < subs.length; i++) {{
        var sub_name = subs[i];
        var n = parseInt("0x" + sub_name.substring(4), 16)
        var sub_ptr = ptr(lib_start).add(ptr(n))
        hook_internal(sub_name, sub_ptr)
    }}
}}
""".format(sublist=round)

all, called = run()
notcalled = all - called

all = sorted(list(all))
called = sorted(list(called))
notcalled = sorted(list(notcalled))