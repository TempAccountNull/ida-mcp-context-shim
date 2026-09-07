// Raw KUSER_SHARED_DATA clock. The kernel maps a read-only copy of _KUSER_SHARED_DATA into
// every process at the fixed user-mode address 0x7FFE0000, so reading the time from it is a
// plain memory load -- no syscall, no QueryPerformanceCounter, no <chrono>.
//
// Self-contained: NO #includes. The fixed-width types, the offset checks (__builtin_offsetof),
// and even a small fixed-capacity String are defined by hand, so this header pulls in nothing
// and cannot collide with the SDK's own types. Layout is the x64 Windows 10 22H2
// _KUSER_SHARED_DATA (https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_KUSER_SHARED_DATA);
// the static_asserts pin sizeof and every offset, so it is provably correct.
#pragma once

namespace kuser {

// Fixed-width base types (MSVC x64 / LLP64), defined by hand so we need no <cstdint>.
using UCHAR     = unsigned char;        // 1
using USHORT    = unsigned short;       // 2
using WCHAR     = unsigned short;       // 2
using ULONG     = unsigned int;         // 4
using LONG      = int;                  // 4
using ULONGLONG = unsigned long long;   // 8
using LONGLONG  = long long;            // 8

// Minimal fixed-capacity string, so string-returning accessors need no <string>. Big enough
// for a Windows path; construct from a literal or build one up with push()/append().
class String
{
public:
  String() {}
  String(const char *s) { append(s); }

  void push(char c)
  {
    if ( len_ + 1 < CAP )
    {
      buf_[len_++] = c;
      buf_[len_] = 0;
    }
  }

  void append(const char *s)
  {
    while ( s != nullptr && *s != 0 )
      push(*s++);
  }

  const char *c_str() const { return buf_; }
  unsigned size() const { return len_; }

private:
  static const unsigned CAP = 288;   // fits NtSystemRoot (<=260 chars) and every timestamp
  char buf_[CAP] = { 0 };
  unsigned len_ = 0;
};

struct _KSYSTEM_TIME
{
  ULONG LowPart;
  LONG High1Time;
  LONG High2Time;
};

union _LARGE_INTEGER
{
  struct { ULONG LowPart; LONG HighPart; };
  struct { ULONG LowPart; LONG HighPart; } u;
  LONGLONG QuadPart;
};

enum _ALTERNATIVE_ARCHITECTURE_TYPE { StandardDesign = 0, NEC98x86 = 1, EndAlternatives = 2 };
enum _NT_PRODUCT_TYPE { NtProductWinNt = 1, NtProductLanManNt = 2, NtProductServer = 3 };

struct _XSTATE_FEATURE
{
  ULONG Offset;
  ULONG Size;
};

struct _XSTATE_CONFIGURATION
{
  ULONGLONG EnabledFeatures;                          // 0x000
  ULONGLONG EnabledVolatileFeatures;                  // 0x008
  ULONG Size;                                         // 0x010
  union                                               // 0x014
  {
    ULONG ControlFlags;
    struct
    {
      ULONG OptimizedSave : 1;
      ULONG CompactionEnabled : 1;
    };
  };
  _XSTATE_FEATURE Features[64];                        // 0x018
  ULONGLONG EnabledSupervisorFeatures;                // 0x218
  ULONGLONG AlignedFeatures;                          // 0x220
  ULONG AllFeatureSize;                               // 0x228
  ULONG AllFeatures[64];                              // 0x22c
  ULONGLONG EnabledUserVisibleSupervisorFeatures;     // 0x330
};
static_assert(sizeof(_XSTATE_CONFIGURATION) == 0x338, "XSTATE_CONFIGURATION size");

struct _KUSER_SHARED_DATA
{
  ULONG TickCountLowDeprecated;                       // 0x000
  ULONG TickCountMultiplier;                          // 0x004
  volatile _KSYSTEM_TIME InterruptTime;               // 0x008  monotonic 100ns tick
  volatile _KSYSTEM_TIME SystemTime;                  // 0x014  wall clock (can jump)
  volatile _KSYSTEM_TIME TimeZoneBias;                // 0x020
  USHORT ImageNumberLow;                              // 0x02c
  USHORT ImageNumberHigh;                             // 0x02e
  WCHAR NtSystemRoot[260];                            // 0x030
  ULONG MaxStackTraceDepth;                           // 0x238
  ULONG CryptoExponent;                               // 0x23c
  ULONG TimeZoneId;                                   // 0x240
  ULONG LargePageMinimum;                             // 0x244
  ULONG AitSamplingValue;                             // 0x248
  ULONG AppCompatFlag;                                // 0x24c
  ULONGLONG RNGSeedVersion;                           // 0x250
  ULONG GlobalValidationRunlevel;                     // 0x258
  volatile LONG TimeZoneBiasStamp;                    // 0x25c
  ULONG NtBuildNumber;                                // 0x260
  _NT_PRODUCT_TYPE NtProductType;                     // 0x264
  UCHAR ProductTypeIsValid;                           // 0x268
  UCHAR Reserved0[1];                                 // 0x269
  USHORT NativeProcessorArchitecture;                 // 0x26a
  ULONG NtMajorVersion;                               // 0x26c
  ULONG NtMinorVersion;                               // 0x270
  UCHAR ProcessorFeatures[64];                        // 0x274
  ULONG Reserved1;                                    // 0x2b4
  ULONG Reserved3;                                    // 0x2b8
  volatile ULONG TimeSlip;                            // 0x2bc
  _ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture; // 0x2c0
  ULONG BootId;                                       // 0x2c4
  _LARGE_INTEGER SystemExpirationDate;                // 0x2c8
  ULONG SuiteMask;                                    // 0x2d0
  UCHAR KdDebuggerEnabled;                            // 0x2d4
  union                                               // 0x2d5
  {
    UCHAR MitigationPolicies;
    struct
    {
      UCHAR NXSupportPolicy : 2;
      UCHAR SEHValidationPolicy : 2;
      UCHAR CurDirDevicesSkippedForDlls : 2;
      UCHAR Reserved : 2;
    };
  };
  USHORT CyclesPerYield;                              // 0x2d6
  volatile ULONG ActiveConsoleId;                     // 0x2d8
  volatile ULONG DismountCount;                       // 0x2dc
  ULONG ComPlusPackage;                               // 0x2e0
  ULONG LastSystemRITEventTickCount;                  // 0x2e4
  ULONG NumberOfPhysicalPages;                        // 0x2e8
  UCHAR SafeBootMode;                                 // 0x2ec
  UCHAR VirtualizationFlags;                          // 0x2ed
  UCHAR Reserved12[2];                                // 0x2ee
  union                                               // 0x2f0
  {
    ULONG SharedDataFlags;
    struct
    {
      ULONG DbgErrorPortPresent : 1;
      ULONG DbgElevationEnabled : 1;
      ULONG DbgVirtEnabled : 1;
      ULONG DbgInstallerDetectEnabled : 1;
      ULONG DbgLkgEnabled : 1;
      ULONG DbgDynProcessorEnabled : 1;
      ULONG DbgConsoleBrokerEnabled : 1;
      ULONG DbgSecureBootEnabled : 1;
      ULONG DbgMultiSessionSku : 1;
      ULONG DbgMultiUsersInSessionSku : 1;
      ULONG DbgStateSeparationEnabled : 1;
      ULONG SpareBits : 21;
    };
  };
  ULONG DataFlagsPad[1];                              // 0x2f4
  ULONGLONG TestRetInstruction;                       // 0x2f8
  LONGLONG QpcFrequency;                              // 0x300
  ULONG SystemCall;                                   // 0x308
  ULONG Reserved2;                                    // 0x30c
  ULONGLONG SystemCallPad[2];                         // 0x310
  union                                               // 0x320
  {
    volatile _KSYSTEM_TIME TickCount;
    volatile ULONGLONG TickCountQuad;                 // forces 8-byte align -> union is 16 bytes
    struct
    {
      ULONG ReservedTickCountOverlay[3];
      ULONG TickCountPad[1];                          // 0x32c, inside the union overlay
    };
  };
  ULONG Cookie;                                       // 0x330
  ULONG CookiePad[1];                                 // 0x334
  LONGLONG ConsoleSessionForegroundProcessId;         // 0x338
  ULONGLONG TimeUpdateLock;                           // 0x340
  ULONGLONG BaselineSystemTimeQpc;                    // 0x348
  ULONGLONG BaselineInterruptTimeQpc;                 // 0x350
  ULONGLONG QpcSystemTimeIncrement;                   // 0x358
  ULONGLONG QpcInterruptTimeIncrement;                // 0x360
  UCHAR QpcSystemTimeIncrementShift;                  // 0x368
  UCHAR QpcInterruptTimeIncrementShift;               // 0x369
  USHORT UnparkedProcessorCount;                      // 0x36a
  ULONG EnclaveFeatureMask[4];                        // 0x36c
  ULONG TelemetryCoverageRound;                       // 0x37c
  USHORT UserModeGlobalLogger[16];                    // 0x380
  ULONG ImageFileExecutionOptions;                    // 0x3a0
  ULONG LangGenerationCount;                          // 0x3a4
  ULONGLONG Reserved4;                                // 0x3a8
  volatile ULONGLONG InterruptTimeBias;               // 0x3b0
  volatile ULONGLONG QpcBias;                         // 0x3b8
  ULONG ActiveProcessorCount;                         // 0x3c0
  volatile UCHAR ActiveGroupCount;                    // 0x3c4
  UCHAR Reserved9;                                    // 0x3c5
  union                                               // 0x3c6
  {
    USHORT QpcData;
    struct
    {
      volatile UCHAR QpcBypassEnabled;
      UCHAR QpcShift;
    };
  };
  _LARGE_INTEGER TimeZoneBiasEffectiveStart;          // 0x3c8
  _LARGE_INTEGER TimeZoneBiasEffectiveEnd;            // 0x3d0
  _XSTATE_CONFIGURATION XState;                       // 0x3d8
  _KSYSTEM_TIME FeatureConfigurationChangeStamp;      // 0x710
  ULONG Spare;                                        // 0x71c
};

static_assert(sizeof(_KSYSTEM_TIME) == 0x0C, "KSYSTEM_TIME size");
static_assert(sizeof(_KUSER_SHARED_DATA) == 0x720, "KUSER_SHARED_DATA size");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, InterruptTime) == 0x08, "InterruptTime offset");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, SystemTime) == 0x14, "SystemTime offset");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, QpcFrequency) == 0x300, "QpcFrequency offset");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, TickCount) == 0x320, "TickCount offset");

// The kernel maps _KUSER_SHARED_DATA read-only at this fixed user-mode address. Resolve the
// pointer ONCE here (inline global, one definition across TUs) instead of re-casting on every
// access; all accessors read through KUSD.
inline const _KUSER_SHARED_DATA *const KUSD =
    reinterpret_cast<const _KUSER_SHARED_DATA *>(0x7FFE0000ull);

// Singleton over the shared page. Accessors are split into small nested classes by domain, so
// you reach one as:
//
//     KUser::get_instance().datetime.get_year()
//     KUser::get_instance().clock.seconds()
//     KUser::get_instance().os.version_string()
//
// That keeps get_instance() itself tiny instead of exposing every field as a flat method. Each
// group is a stateless handle; every read goes straight through KUSD -- no QPC, no syscall.
class KUser
{
public:
  KUser(const KUser &) = delete;
  KUser &operator=(const KUser &) = delete;

  static KUser &get_instance()
  {
    static KUser instance;   // thread-safe init (C++11+); the mapping is process-wide
    return instance;
  }

  // Broken-down calendar time, returned by the DateTime group's now_utc()/now_local().
  struct Timestamp
  {
    int year;
    unsigned month;        // 1-12
    unsigned day;          // 1-31
    unsigned hour;         // 0-23
    unsigned minute;       // 0-59
    unsigned second;       // 0-59
    unsigned millisecond;  // 0-999
    unsigned weekday;      // 0=Sunday .. 6=Saturday
  };

  // ---- monotonic time: get_instance().clock.<method>() ----
  // The right source for elapsed/duration -- never jumps.
  struct Clock
  {
    ULONGLONG interrupt_time_100ns() const
    {
      return read_ksystime(&KUSD->InterruptTime);
    }

    ULONGLONG interrupt_time_ns() const   // nanoseconds since boot
    {
      return interrupt_time_100ns() * 100;
    }

    double seconds() const   // since boot
    {
      return double(interrupt_time_100ns()) * 1e-7;
    }

    ULONGLONG uptime_ms() const   // since boot
    {
      return interrupt_time_100ns() / 10000;
    }

    String uptime_string() const   // "5d 07h 08m 16s"
    {
      ULONGLONG s = interrupt_time_100ns() / 10000000ull;
      String out;
      append_num(out, unsigned(s / 86400), 1);
      out.append("d ");
      append_num(out, unsigned((s % 86400) / 3600), 2);
      out.append("h ");
      append_num(out, unsigned((s % 3600) / 60), 2);
      out.append("m ");
      append_num(out, unsigned(s % 60), 2);
      out.push('s');
      return out;
    }

    ULONGLONG interrupt_time_bias() const
    {
      return KUSD->InterruptTimeBias;
    }

    ULONGLONG tick_count() const
    {
      return KUSD->TickCountQuad;
    }

    ULONG tick_count_multiplier() const
    {
      return KUSD->TickCountMultiplier;
    }

    LONGLONG qpc_frequency() const
    {
      return KUSD->QpcFrequency;
    }

    ULONGLONG qpc_bias() const
    {
      return KUSD->QpcBias;
    }

    bool qpc_bypass_enabled() const
    {
      return KUSD->QpcBypassEnabled != 0;
    }
  } clock;

  // ---- wall clock + calendar: get_instance().datetime.<method>() ----
  // Time of day; can jump on NTP/DST -- never use for durations.
  struct DateTime
  {
    ULONGLONG system_time_100ns() const   // 100ns since 1601-01-01 (FILETIME epoch)
    {
      return read_ksystime(&KUSD->SystemTime);
    }

    double unix_time() const   // seconds since 1970-01-01
    {
      return double(system_time_100ns() - 116444736000000000ull) * 1e-7;
    }

    ULONGLONG unix_time_ms() const   // milliseconds since 1970-01-01
    {
      return (system_time_100ns() - 116444736000000000ull) / 10000;
    }

    ULONGLONG time_zone_bias_100ns() const
    {
      return read_ksystime(&KUSD->TimeZoneBias);
    }

    ULONG time_zone_id() const
    {
      return KUSD->TimeZoneId;
    }

    Timestamp now_utc() const
    {
      return to_datetime(system_time_100ns());
    }

    Timestamp now_local() const   // UTC minus the current TZ (+DST) bias
    {
      return to_datetime(system_time_100ns() - time_zone_bias_100ns());
    }

    int get_year() const
    {
      return now_utc().year;
    }

    unsigned get_month() const
    {
      return now_utc().month;
    }

    unsigned get_day() const
    {
      return now_utc().day;
    }

    unsigned get_hour() const
    {
      return now_utc().hour;
    }

    unsigned get_minute() const
    {
      return now_utc().minute;
    }

    unsigned get_second() const
    {
      return now_utc().second;
    }

    unsigned get_millisecond() const
    {
      return now_utc().millisecond;
    }

    unsigned get_weekday() const
    {
      return now_utc().weekday;
    }

    unsigned day_of_year() const   // 1-366
    {
      Timestamp t = now_utc();
      static const unsigned cum[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
      unsigned doy = cum[(t.month >= 1 && t.month <= 12) ? t.month - 1 : 0] + t.day;
      bool leap = (t.year % 4 == 0 && t.year % 100 != 0) || (t.year % 400 == 0);
      if ( leap && t.month > 2 )
        doy += 1;
      return doy;
    }

    String weekday_name() const   // "Monday"
    {
      static const char *const names[7] =
        { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
      unsigned w = now_utc().weekday;
      return names[w < 7 ? w : 0];
    }

    String month_name() const   // "September"
    {
      static const char *const names[12] =
        { "January", "February", "March", "April", "May", "June",
          "July", "August", "September", "October", "November", "December" };
      unsigned m = now_utc().month;
      return names[(m >= 1 && m <= 12) ? m - 1 : 0];
    }

    String to_string() const         // "YYYY-MM-DD HH:MM:SS" (UTC)
    {
      return ymdhms(now_utc());
    }

    String to_string_local() const   // "YYYY-MM-DD HH:MM:SS" (wall-local)
    {
      return ymdhms(now_local());
    }

    String iso8601() const   // "2026-09-07T04:55:00.242Z" (UTC)
    {
      Timestamp t = now_utc();
      String s;
      append_num(s, unsigned(t.year), 4);
      s.push('-');
      append_num(s, t.month, 2);
      s.push('-');
      append_num(s, t.day, 2);
      s.push('T');
      append_num(s, t.hour, 2);
      s.push(':');
      append_num(s, t.minute, 2);
      s.push(':');
      append_num(s, t.second, 2);
      s.push('.');
      append_num(s, t.millisecond, 3);
      s.push('Z');
      return s;
    }
  } datetime;

  // ---- OS identity: get_instance().os.<method>() ----
  struct OsInfo
  {
    ULONG build_number() const
    {
      return KUSD->NtBuildNumber;
    }

    ULONG major_version() const
    {
      return KUSD->NtMajorVersion;
    }

    ULONG minor_version() const
    {
      return KUSD->NtMinorVersion;
    }

    String version_string() const   // "10.0.19045"
    {
      String s;
      append_num(s, major_version(), 1);
      s.push('.');
      append_num(s, minor_version(), 1);
      s.push('.');
      append_num(s, build_number(), 1);
      return s;
    }

    _NT_PRODUCT_TYPE product_type() const
    {
      return KUSD->NtProductType;
    }

    String product_type_name() const
    {
      switch ( KUSD->NtProductType )
      {
        case NtProductWinNt:    return "Workstation";
        case NtProductLanManNt: return "Domain Controller";
        case NtProductServer:   return "Server";
        default:                return "Unknown";
      }
    }

    bool is_server() const
    {
      return KUSD->NtProductType != NtProductWinNt;
    }

    USHORT processor_architecture() const
    {
      return KUSD->NativeProcessorArchitecture;
    }

    String processor_architecture_name() const
    {
      switch ( KUSD->NativeProcessorArchitecture )
      {
        case 0:  return "x86";
        case 5:  return "ARM";
        case 6:  return "IA64";
        case 9:  return "x64";
        case 12: return "ARM64";
        default: return "Unknown";
      }
    }

    ULONG boot_id() const
    {
      return KUSD->BootId;
    }

    ULONG suite_mask() const
    {
      return KUSD->SuiteMask;
    }

    String system_root() const   // "C:\Windows"
    {
      String s;
      for ( int i = 0; i < 260 && KUSD->NtSystemRoot[i] != 0; ++i )
        s.push(char(KUSD->NtSystemRoot[i]));   // system root is ASCII
      return s;
    }
  } os;

  // ---- hardware / CPU: get_instance().cpu.<method>() ----
  struct Cpu
  {
    ULONG processor_count() const
    {
      return KUSD->ActiveProcessorCount;
    }

    unsigned active_group_count() const
    {
      return KUSD->ActiveGroupCount;
    }

    USHORT unparked_processor_count() const
    {
      return KUSD->UnparkedProcessorCount;
    }

    USHORT cycles_per_yield() const
    {
      return KUSD->CyclesPerYield;
    }

    ULONG physical_pages() const
    {
      return KUSD->NumberOfPhysicalPages;
    }

    ULONGLONG physical_memory_bytes() const
    {
      return ULONGLONG(KUSD->NumberOfPhysicalPages) * 4096ull;
    }

    ULONG large_page_minimum() const
    {
      return KUSD->LargePageMinimum;
    }

    // A PF_* processor-feature flag (e.g. PF_XMMI64_INSTRUCTIONS_AVAILABLE); false if out of range.
    bool is_feature_present(unsigned feature) const
    {
      return feature < 64 && KUSD->ProcessorFeatures[feature] != 0;
    }

    bool has_sse2() const { return is_feature_present(10); }   // PF_XMMI64_INSTRUCTIONS_AVAILABLE
    bool has_sse3() const { return is_feature_present(13); }   // PF_SSE3_INSTRUCTIONS_AVAILABLE
    bool has_nx()   const { return is_feature_present(12); }   // PF_NX_ENABLED (DEP)
  } cpu;

  // ---- security / debug state: get_instance().security.<method>() ----
  struct Security
  {
    bool kd_debugger_enabled() const   // boot /DEBUG flag
    {
      return KUSD->KdDebuggerEnabled != 0;
    }

    bool safe_boot_mode() const
    {
      return KUSD->SafeBootMode != 0;
    }

    bool secure_boot_enabled() const
    {
      return KUSD->DbgSecureBootEnabled != 0;
    }

    bool dbg_elevation_enabled() const
    {
      return KUSD->DbgElevationEnabled != 0;
    }

    bool dbg_virt_enabled() const
    {
      return KUSD->DbgVirtEnabled != 0;
    }

    unsigned nx_support_policy() const    // 0=AlwaysOff 1=AlwaysOn 2=OptIn 3=OptOut
    {
      return KUSD->NXSupportPolicy;
    }

    unsigned seh_validation_policy() const
    {
      return KUSD->SEHValidationPolicy;
    }

    ULONG shared_data_flags() const
    {
      return KUSD->SharedDataFlags;
    }

    ULONG cookie() const   // SharedUserData cookie (pointer-encoding seed)
    {
      return KUSD->Cookie;
    }
  } security;

  // Raw page, for any field not wrapped by a group above.
  const _KUSER_SHARED_DATA *data() const
  {
    return KUSD;
  }

private:
  KUser() = default;

  // KSYSTEM_TIME is written by the kernel as three 32-bit fields, so re-read until the two
  // High words agree -- that rejects a torn value straddling a kernel update.
  static ULONGLONG read_ksystime(const volatile _KSYSTEM_TIME *time_ptr)
  {
    for ( ;; )
    {
      LONG high1 = time_ptr->High1Time;
      ULONG low  = time_ptr->LowPart;
      LONG high2 = time_ptr->High2Time;
      if ( high1 == high2 )
        return (ULONGLONG(ULONG(high1)) << 32) | low;
    }
  }

  // Civil calendar from a FILETIME (100ns since 1601-01-01 UTC). Pure arithmetic (Howard
  // Hinnant's days<->civil algorithm) -- no FileTimeToSystemTime, no kernel call.
  static Timestamp to_datetime(ULONGLONG filetime_100ns)
  {
    const ULONGLONG sec_1601 = filetime_100ns / 10000000ull;
    LONGLONG unix_sec = LONGLONG(sec_1601) - 11644473600ll;   // 1601-01-01 -> 1970-01-01
    LONGLONG days = unix_sec / 86400;
    LONGLONG sod = unix_sec % 86400;
    if ( sod < 0 )   // floor toward -infinity (guards pre-1970 inputs)
    {
      sod += 86400;
      --days;
    }
    int y;
    unsigned mo, d;
    civil_from_days(days, y, mo, d);
    Timestamp dt = {};
    dt.year = y;
    dt.month = mo;
    dt.day = d;
    dt.hour = unsigned(sod / 3600);
    dt.minute = unsigned((sod % 3600) / 60);
    dt.second = unsigned(sod % 60);
    dt.millisecond = unsigned((filetime_100ns / 10000ull) % 1000ull);
    LONGLONG wd = (days % 7 + 4) % 7;   // 1970-01-01 was a Thursday (=4)
    if ( wd < 0 )
      wd += 7;
    dt.weekday = unsigned(wd);
    return dt;
  }

  // days since 1970-01-01 -> civil (year, month [1,12], day [1,31]).
  static void civil_from_days(LONGLONG z, int &y, unsigned &m, unsigned &d)
  {
    z += 719468;   // shift the epoch to 0000-03-01
    const LONGLONG era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = unsigned(z - era * 146097);                             // [0, 146096]
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;  // [0, 399]
    const LONGLONG yr = LONGLONG(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                // [0, 365]
    const unsigned mp = (5 * doy + 2) / 153;                                     // [0, 11]
    d = doy - (153 * mp + 2) / 5 + 1;                                            // [1, 31]
    m = mp < 10 ? mp + 3 : mp - 9;                                               // [1, 12]
    y = int(yr) + (m <= 2);
  }

  // "YYYY-MM-DD HH:MM:SS" from a broken-down time.
  static String ymdhms(const Timestamp &t)
  {
    String s;
    append_num(s, unsigned(t.year), 4);
    s.push('-');
    append_num(s, t.month, 2);
    s.push('-');
    append_num(s, t.day, 2);
    s.push(' ');
    append_num(s, t.hour, 2);
    s.push(':');
    append_num(s, t.minute, 2);
    s.push(':');
    append_num(s, t.second, 2);
    return s;
  }

  // Append `value` to `s` as decimal digits, zero-padded to at least `width`.
  static void append_num(String &s, unsigned value, int width)
  {
    char buf[16];
    int n = 0;
    do
    {
      buf[n++] = char('0' + value % 10);
      value /= 10;
    } while ( value != 0 );
    for ( int i = n; i < width; ++i )
      s.push('0');
    while ( n > 0 )
      s.push(buf[--n]);
  }
};

}  // namespace kuser

using kuser::KUser;
