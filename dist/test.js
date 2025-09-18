"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("./index");
if (index_1.WinHID) {
    const hid = new index_1.WinHID();
    const devices = hid.getDevices().filter(d => d.usage == 4 && d.usagePage == 1);
    console.log(devices);
    hid.startListening({ usagePage: 1, usage: 4 }, (evt) => console.log(evt));
    setTimeout(() => {
        hid.stopListening();
    }, 20000);
}
//# sourceMappingURL=test.js.map