#ifdef _WIN32
#define NOMINMAX
#include "WinHID.h"
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <cfgmgr32.h>
#include <vector>
#include <unordered_set>
#include <chrono>
#include <mutex>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

// ---------- helpers ----------
static std::string wstr_to_utf8(const wchar_t* w) {
  if (!w) return {};
  int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  if (len <= 0) return {};
  std::string s(len - 1, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
  return s;
}
static std::string wstr_to_utf8(const std::wstring& w) { return wstr_to_utf8(w.c_str()); }

std::string WinHID::WToU8(const wchar_t* w){ return wstr_to_utf8(w); }
std::string WinHID::WToU8(const std::wstring& w){ return wstr_to_utf8(w); }

bool WinHID::OpenHid(const std::wstring& path, HANDLE& out) {
  HANDLE h = CreateFileW(path.c_str(),
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING,
                         FILE_FLAG_OVERLAPPED, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    h = CreateFileW(path.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED, nullptr);
  }
  if (h == INVALID_HANDLE_VALUE) return false;
  out = h;
  return true;
}

bool WinHID::GetCaps(HANDLE h, USHORT& usagePage, USHORT& usage, USHORT& inLen) {
  PHIDP_PREPARSED_DATA prep = nullptr;
  HIDP_CAPS caps;
  if (!HidD_GetPreparsedData(h, &prep)) return false;
  NTSTATUS st = HidP_GetCaps(prep, &caps);
  HidD_FreePreparsedData(prep);
  if (st != HIDP_STATUS_SUCCESS) return false;
  usagePage = caps.UsagePage;
  usage = caps.Usage;
  inLen = caps.InputReportByteLength;
  return inLen > 0;
}

// ---------- ctor and class ----------
WinHID::WinHID(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<WinHID>(info) {}

Napi::Function WinHID::GetClass(Napi::Env env) {
  return DefineClass(env, "WinHID", {
    InstanceMethod("getDevices", &WinHID::GetDevices),
    InstanceMethod("startListening", &WinHID::StartListening),
    InstanceMethod("stopListening", &WinHID::StopListening),
  });
}



Napi::Value WinHID::GetDevices(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  GUID hidGuid;
  HidD_GetHidGuid(&hidGuid);

  HDEVINFO devInfo = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (devInfo == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "SetupDiGetClassDevs failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Array result = Napi::Array::New(env);
  DWORD index = 0;
  SP_DEVICE_INTERFACE_DATA ifData;
  ifData.cbSize = sizeof(ifData);

  while (SetupDiEnumDeviceInterfaces(devInfo, nullptr, &hidGuid, index, &ifData)) {
    ++index;

    // First call to get required size
    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, nullptr, 0, &requiredSize, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0) {
      continue;
    }

    std::vector<BYTE> buffer(requiredSize);
    auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(devData);

    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, requiredSize, nullptr, &devData)) {
      continue;
    }

    std::wstring devicePathW(detail->DevicePath);
    std::string devicePath = wstr_to_utf8(devicePathW);

    // Open device to query attributes and strings
    HANDLE h = CreateFileW(detail->DevicePath,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      // Try read-only
      h = CreateFileW(detail->DevicePath,
                      0,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      nullptr,
                      OPEN_EXISTING,
                      FILE_FLAG_OVERLAPPED,
                      nullptr);
    }

    USHORT vid = 0, pid = 0;
    USHORT usagePage = 0, usage = 0;
    std::string manufacturer, product, serial;

    if (h != INVALID_HANDLE_VALUE) {
      HIDD_ATTRIBUTES attrs;
      attrs.Size = sizeof(attrs);
      if (HidD_GetAttributes(h, &attrs)) {
        vid = attrs.VendorID;
        pid = attrs.ProductID;
      }

      PHIDP_PREPARSED_DATA prep = nullptr;
      HIDP_CAPS caps;
      if (HidD_GetPreparsedData(h, &prep)) {
        if (HidP_GetCaps(prep, &caps) == HIDP_STATUS_SUCCESS) {
          usagePage = caps.UsagePage;
          usage = caps.Usage;
        }
        HidD_FreePreparsedData(prep);
      }

      wchar_t wbuf[256];
      if (HidD_GetManufacturerString(h, wbuf, sizeof(wbuf))) {
        manufacturer = wstr_to_utf8(wbuf);
      }
      if (HidD_GetProductString(h, wbuf, sizeof(wbuf))) {
        product = wstr_to_utf8(wbuf);
      }
      if (HidD_GetSerialNumberString(h, wbuf, sizeof(wbuf))) {
        serial = wstr_to_utf8(wbuf);
      }

      CloseHandle(h);
    }

    Napi::Object dev = Napi::Object::New(env);
    dev.Set("path", devicePath);
    dev.Set("vendorId", Napi::Number::New(env, vid));
    dev.Set("productId", Napi::Number::New(env, pid));
    dev.Set("usagePage", Napi::Number::New(env, usagePage));
    dev.Set("usage", Napi::Number::New(env, usage));
    if (!manufacturer.empty()) dev.Set("manufacturer", Napi::String::New(env, manufacturer));
    if (!product.empty())      dev.Set("product", Napi::String::New(env, product));
    if (!serial.empty())       dev.Set("serialNumber", Napi::String::New(env, serial));

    result.Set(result.Length(), dev);
  }

  SetupDiDestroyDeviceInfoList(devInfo);
  return result;
}

// ---------- reader thread ----------
void WinHID::RunReader(std::shared_ptr<Listener> L) {
  // Pre-parse button caps once
  PHIDP_PREPARSED_DATA prep = nullptr;
  if (!HidD_GetPreparsedData(L->handle, &prep)) return;

  HIDP_CAPS caps{};
  if (HidP_GetCaps(prep, &caps) != HIDP_STATUS_SUCCESS) { HidD_FreePreparsedData(prep); return; }

  USHORT numBtnCaps = caps.NumberInputButtonCaps;
  std::vector<HIDP_BUTTON_CAPS> btnCaps(numBtnCaps ? numBtnCaps : 1);
  if (numBtnCaps) HidP_GetButtonCaps(HidP_Input, btnCaps.data(), &numBtnCaps, prep);

  // Prepare count upper bound for usages buffer
  ULONG maxUsages = 64;
  for (USHORT i = 0; i < numBtnCaps; ++i) {
    ULONG range = (btnCaps[i].IsRange)
      ? (btnCaps[i].Range.UsageMax - btnCaps[i].Range.UsageMin + 1)
      : 1;
    if (range > maxUsages) maxUsages = range;
  }

  std::vector<BYTE> report(caps.InputReportByteLength);
  std::vector<BYTE> lastReport = L->prevReport.empty() ? std::vector<BYTE>(caps.InputReportByteLength) : L->prevReport;

  OVERLAPPED ov{};
  ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

  while (!L->stop.load()) {
    DWORD bytesRead = 0;
    ResetEvent(ov.hEvent);
    BOOL ok = ReadFile(L->handle, report.data(), (DWORD)report.size(), nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(ov.hEvent, 20); // poll at 20ms
        if (wait == WAIT_OBJECT_0) {
          GetOverlappedResult(L->handle, &ov, &bytesRead, FALSE);
        } else if (wait == WAIT_TIMEOUT) {
          continue;
        } else {
          break;
        }
      } else {
        break;
      }
    } else {
      GetOverlappedResult(L->handle, &ov, &bytesRead, TRUE);
    }
    if (bytesRead == 0) continue;

    // Collect pressed buttons
    std::unordered_set<USHORT> pressed;
    for (USHORT i = 0; i < numBtnCaps; ++i) {
      if (btnCaps[i].UsagePage != 0 && L->usagePage && btnCaps[i].UsagePage != L->usagePage) continue;
      ULONG cnt = maxUsages;
      std::vector<USAGE> usages(cnt);
      NTSTATUS s = HidP_GetUsages(HidP_Input,
                                  btnCaps[i].UsagePage,
                                  0,
                                  usages.data(),
                                  &cnt,
                                  prep,
                                  (PCHAR)report.data(),
                                  (ULONG)report.size());
      if (s == HIDP_STATUS_SUCCESS) {
        for (ULONG k = 0; k < cnt; ++k) {
          pressed.insert((USHORT)usages[k]);
        }
      }
    }

    // Diff with previous pressed set
    std::unordered_set<USHORT> prevPressed;
    if (!lastReport.empty()) {
      for (USHORT i = 0; i < numBtnCaps; ++i) {
        if (btnCaps[i].UsagePage != 0 && L->usagePage && btnCaps[i].UsagePage != L->usagePage) continue;
        ULONG cnt = maxUsages;
        std::vector<USAGE> usages(cnt);
        NTSTATUS s = HidP_GetUsages(HidP_Input,
                                    btnCaps[i].UsagePage,
                                    0,
                                    usages.data(),
                                    &cnt,
                                    prep,
                                    (PCHAR)lastReport.data(),
                                    (ULONG)lastReport.size());
        if (s == HIDP_STATUS_SUCCESS) {
          for (ULONG k = 0; k < cnt; ++k) prevPressed.insert((USHORT)usages[k]);
        }
      }
    }

    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();

    // Emits for presses
    for (auto u : pressed) {
      if (!prevPressed.count(u)) {
        L->tsfn.BlockingCall([L, u, now](Napi::Env env, Napi::Function cb){
          Napi::Object evt = Napi::Object::New(env);
          evt.Set("path", Napi::String::New(env, WinHID::WToU8(L->pathW)));
          evt.Set("usagePage", Napi::Number::New(env, L->usagePage));
          evt.Set("usage", Napi::Number::New(env, L->usage));
          evt.Set("button", Napi::Number::New(env, u));
          evt.Set("pressed", Napi::Boolean::New(env, true));
          evt.Set("timestamp", Napi::Number::New(env, (double)now));
          cb.Call({ evt });
        });
      }
    }
    // Emits for releases
    for (auto u : prevPressed) {
      if (!pressed.count(u)) {
        L->tsfn.BlockingCall([L, u, now](Napi::Env env, Napi::Function cb){
          Napi::Object evt = Napi::Object::New(env);
          evt.Set("path", Napi::String::New(env, WinHID::WToU8(L->pathW)));
          evt.Set("usagePage", Napi::Number::New(env, L->usagePage));
          evt.Set("usage", Napi::Number::New(env, L->usage));
          evt.Set("button", Napi::Number::New(env, u));
          evt.Set("pressed", Napi::Boolean::New(env, false));
          evt.Set("timestamp", Napi::Number::New(env, (double)now));
          cb.Call({ evt });
        });
      }
    }

    lastReport = report;
  }

  if (ov.hEvent) CloseHandle(ov.hEvent);
  HidD_FreePreparsedData(prep);
}

// ---------- API: start/stop ----------
Napi::Value WinHID::StartListening(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  // Args: (filter?, callback)
  int cbIndex = (info.Length() >= 1 && info[0].IsFunction()) ? 0 : 1;
  if (info.Length() <= cbIndex || !info[cbIndex].IsFunction()) {
    Napi::TypeError::New(env, "callback function is required").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  Napi::Function cb = info[cbIndex].As<Napi::Function>();

  USHORT wantVid = 0, wantPid = 0, wantUsagePage = 0, wantUsage = 0;
  if (cbIndex == 1 && info[0].IsObject()) {
    Napi::Object f = info[0].As<Napi::Object>();
    if (f.Has("vendorId"))   wantVid = (USHORT)f.Get("vendorId").ToNumber().Uint32Value();
    if (f.Has("productId"))  wantPid = (USHORT)f.Get("productId").ToNumber().Uint32Value();
    if (f.Has("usagePage"))  wantUsagePage = (USHORT)f.Get("usagePage").ToNumber().Uint32Value();
    if (f.Has("usage"))      wantUsage = (USHORT)f.Get("usage").ToNumber().Uint32Value();
  }

  // enumerate devices (reuse GetDevices logic but inline for perf)
  GUID hidGuid; HidD_GetHidGuid(&hidGuid);
  HDEVINFO devInfo = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (devInfo == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "SetupDiGetClassDevs failed").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  DWORD index = 0;
  SP_DEVICE_INTERFACE_DATA ifData; ifData.cbSize = sizeof(ifData);

  // ThreadSafeFunction shared across listeners? Use per-listener to keep life cycle simple.
  while (SetupDiEnumDeviceInterfaces(devInfo, nullptr, &hidGuid, index, &ifData)) {
    ++index;
    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, nullptr, 0, &requiredSize, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0) continue;
    std::vector<BYTE> buffer(requiredSize);
    auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    SP_DEVINFO_DATA devData; devData.cbSize = sizeof(devData);
    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, requiredSize, nullptr, &devData)) continue;

    std::wstring pathW(detail->DevicePath);
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenHid(pathW, h)) continue;

    // Filter via VID/PID if provided
    bool pass = true;
    if (wantVid || wantPid) {
      HIDD_ATTRIBUTES attrs; attrs.Size = sizeof(attrs);
      if (HidD_GetAttributes(h, &attrs)) {
        if (wantVid && attrs.VendorID != wantVid) pass = false;
        if (wantPid && attrs.ProductID != wantPid) pass = false;
      }
    }
    USHORT usagePage=0, usage=0, inLen=0;
    if (pass) pass = GetCaps(h, usagePage, usage, inLen);
    if (pass && wantUsagePage && usagePage != wantUsagePage) pass = false;
    if (pass && wantUsage && usage != wantUsage) pass = false;

    if (!pass) { CloseHandle(h); continue; }

    auto L = std::make_shared<Listener>();
    L->pathW = pathW;
    L->handle = h;
    L->usagePage = usagePage;
    L->usage = usage;
    L->inputReportLen = inLen;
    L->prevReport.assign(inLen, 0);

    // Create TSFN
    L->tsfn = Napi::ThreadSafeFunction::New(
      env, cb, "hid-button-listener", 0, 1);

    std::string key = WToU8(pathW);
    // Start thread first so L stays alive via shared_ptr captured by lambda.
    L->th = std::thread([L]{ RunReader(L); });

    // Put into map with unique_ptr to manage lifetime; also keep handle for stop
    listeners_[key] = std::move(L);
  }

  SetupDiDestroyDeviceInfoList(devInfo);
  return env.Undefined();
}

void WinHID::stopAll() {
  for (auto& kv : listeners_) {
    Listener* L = kv.second.get();
    if (!L) continue;
    L->stop.store(true);
    if (L->handle != INVALID_HANDLE_VALUE) {
      CancelIoEx(L->handle, nullptr);
    }
  }
  for (auto& kv : listeners_) {
    Listener* L = kv.second.get();
    if (!L) continue;
    if (L->th.joinable()) L->th.join();
    if (L->tsfn) { L->tsfn.Release(); }
    if (L->handle != INVALID_HANDLE_VALUE) {
      CloseHandle(L->handle);
      L->handle = INVALID_HANDLE_VALUE;
    }
  }
  listeners_.clear();
}

Napi::Value WinHID::StopListening(const Napi::CallbackInfo& info) {
  stopAll();
  return info.Env().Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    Napi::String name = Napi::String::New(env, "WinHID");
    exports.Set(name, WinHID::GetClass(env));
    return exports;
}

NODE_API_MODULE(addon, Init)

#endif
