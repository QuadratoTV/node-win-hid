import { WinHID } from "./index";

if (WinHID) {
  const hid = new WinHID();
  const devices = hid.getDevices().filter(d => d.usage == 4 && d.usagePage == 1);
  console.log(devices);

  hid.startListening({ usagePage: 1, usage: 4 }, (evt) => console.log(evt));

  setTimeout(() => {
    hid.stopListening();
  }, 20000);
}
