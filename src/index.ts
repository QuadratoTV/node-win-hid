import { WinHID } from "./bindings";

if (WinHID) {
  const hid = new WinHID();
  const devices = hid.getDevices();
  console.log(devices);

  hid.startListening({}, (evt) => {
    console.log(evt);
  });

  setTimeout(() => {
    hid.stopListening();
  }, 20000);
}