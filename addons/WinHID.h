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

  Napi::Value GetDevices(const Napi::CallbackInfo& info);
  // startListening(filter?, callback)
  Napi::Value StartListening(const Napi::CallbackInfo& info);
  Napi::Value StopListening(const Napi::CallbackInfo& info);

private:
  struct Listener {
    std::wstring pathW;
    std::string  pathNormU8;   // lowercased \\\\?\\hid#...
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::thread th;
    std::atomic<bool> stop{false};
    Napi::ThreadSafeFunction tsfn;
    USHORT usagePage = 0;
    USHORT usage = 0;
    USHORT inputReportLen = 0;
    std::vector<BYTE> prevReport;

    // identity info for consistent labeling
    USHORT vid = 0, pid = 0;
    std::string containerId;   // GUID string
    std::string manufacturer, product, serial;
  };

  std::unordered_map<std::string, std::shared_ptr<Listener>> listeners_; // keyed by pathNormU8
  std::mutex listeners_mtx_;

  Napi::ThreadSafeFunction tsfn_;
  bool tsfn_ready_ = false;

  USHORT wantVid_ = 0, wantPid_ = 0, wantUsagePage_ = 0, wantUsage_ = 0;

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
