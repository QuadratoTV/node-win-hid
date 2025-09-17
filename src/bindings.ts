const addon = require('../build/node-win-hid.node') as {
  WinHID: new () => {
    getDevices(): Array<{
      path: string; vendorId: number; productId: number;
      usagePage: number; usage: number;
      manufacturer?: string; product?: string; serialNumber?: string;
    }>;
    startListening(
      filterOrCb?: {
        vendorId?: number; productId?: number; usagePage?: number; usage?: number;
      } | ((evt: {
        path: string; usagePage: number; usage: number;
        button: number; pressed: boolean; timestamp: number;
      }) => void),
      cb?: (evt: {
        path: string; usagePage: number; usage: number;
        button: number; pressed: boolean; timestamp: number;
      }) => void
    ): void;
    stopListening(): void;
  };
};

export const WinHID = addon.WinHID;