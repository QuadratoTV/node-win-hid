#pragma once
#ifdef _WIN32

#include <napi.h>
#include <map>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <windows.h>
#include <cfgmgr32.h>

class WinHID : public Napi::ObjectWrap<WinHID> {
public:
  explicit WinHID(const Napi::CallbackInfo& info);
  ~WinHID();
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

  // active readers by symbolic link path (UTF-8)
  std::unordered_map<std::string, std::shared_ptr<Listener>> listeners_;
  std::mutex listeners_mtx_;

  // stored JS callback for future hot-plug readers
  Napi::FunctionReference cbRef_;

  // filter requested by user
  USHORT wantVid_ = 0, wantPid_ = 0, wantUsagePage_ = 0, wantUsage_ = 0;

  // PnP notification handle
  HCMNOTIFICATION pnpNotify_ = nullptr;

  // helpers
  static bool OpenHid(const std::wstring& path, HANDLE& out);
  static bool GetCaps(HANDLE h, USHORT& usagePage, USHORT& usage, USHORT& inLen);
  static std::string WToU8(const wchar_t* w);
  static std::string WToU8(const std::wstring& w);
  static void RunReader(std::shared_ptr<Listener> L);
  void stopAll();

  // hot-plug helpers
  void startReaderForPath(const std::wstring& pathW);
  void stopReaderForPath(const std::wstring& pathW);

  // CM_Register_Notification callback
  static DWORD CALLBACK OnPnpEvent(HCMNOTIFICATION h, PVOID ctx,
                                   CM_NOTIFY_ACTION action,
                                   PCM_NOTIFY_EVENT_DATA data, DWORD eventDataSize);
};

#endif
