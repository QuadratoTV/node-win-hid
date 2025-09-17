#pragma once
#ifdef _WIN32

#include <napi.h>
#include <map>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <windows.h>

class WinHID : public Napi::ObjectWrap<WinHID> {
public:
  explicit WinHID(const Napi::CallbackInfo& info);
  static Napi::Function GetClass(Napi::Env env);

  // JS: new WinHID().getDevices(): Array<...>
  Napi::Value GetDevices(const Napi::CallbackInfo& info);

  // JS: new WinHID().startListening(filter?, callback)
  // filter?: { vendorId?, productId?, usagePage?, usage? }
  Napi::Value StartListening(const Napi::CallbackInfo& info);

  // JS: new WinHID().stopListening()  // stops all threads and releases handles
  Napi::Value StopListening(const Napi::CallbackInfo& info);

private:
  struct Listener {
    std::wstring pathW;
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::thread th;
    std::atomic<bool> stop{false};
    Napi::ThreadSafeFunction tsfn;
    USHORT usagePage = 0;
    USHORT usage = 0;
    USHORT inputReportLen = 0;
    std::vector<BYTE> prevReport;
  };

  std::unordered_map<std::string, std::shared_ptr<Listener>> listeners_;

  static bool OpenHid(const std::wstring& path, HANDLE& out);
  static bool GetCaps(HANDLE h, USHORT& usagePage, USHORT& usage, USHORT& inLen);
  static std::string WToU8(const wchar_t* w);
  static std::string WToU8(const std::wstring& w);
  static void RunReader(std::shared_ptr<Listener> L);
  void stopAll();
};

#endif
