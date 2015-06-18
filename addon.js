var addon = require('./build/debug/injector');

var process_id = addon.get_process_id('calc.exe');

var injected = addon.is_dll_injected(process_id, 'mydll.dll');

if (!injected)
    addon.inject_dll(process_id, '/path/to/mydll.dll');

console.log(addon.is_dll_injected(process_id, 'mydll.dll'));

