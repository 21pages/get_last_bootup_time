#include <Windows.h>
#include <stdio.h>

#include <memory>
#include <string>
#include <vector>

// from: https://github.com/boostorg/boost/releases/tag/boost-1.83.0
// boost/interprocess/detail/win32_api.hpp
// why not using SESSION_MANAGER_BASED?
// line 1626 &&
// https://stackoverflow.com/questions/69238288/how-to-convert-the-output-of-boostinterprocesswinapiget-last-bootup-time

namespace {
static const unsigned long eventlog_sequential_read = 0x0001;
static const unsigned long eventlog_backwards_read = 0x0008;
static const unsigned long max_record_buffer_size = 0x10000L;  // 64K
static const unsigned long error_insufficient_buffer = 122L;
inline static unsigned long get_last_error() { return GetLastError(); }
inline static unsigned int close_handle(void *handle) {
  return CloseHandle(handle);
}

struct interprocess_eventlogrecord {
  unsigned long Length;         // Length of full record
  unsigned long Reserved;       // Used by the service
  unsigned long RecordNumber;   // Absolute record number
  unsigned long TimeGenerated;  // Seconds since 1-1-1970
  unsigned long TimeWritten;    // Seconds since 1-1-1970
  unsigned long EventID;
  unsigned short EventType;
  unsigned short NumStrings;
  unsigned short EventCategory;
  unsigned short ReservedFlags;       // For use with paired events (auditing)
  unsigned long ClosingRecordNumber;  // For use with paired events (auditing)
  unsigned long StringOffset;         // Offset from beginning of record
  unsigned long UserSidLength;
  unsigned long UserSidOffset;
  unsigned long DataLength;
  unsigned long DataOffset;  // Offset from beginning of record
                             //
                             // Then follow:
                             //
                             // wchar_t SourceName[]
                             // wchar_t Computername[]
                             // SID   UserSid
                             // wchar_t Strings[]
                             // BYTE  Data[]
                             // CHAR  Pad[]
                             // unsigned long Length;
                             //
};

class handle_closer {
  void *handle_;
  handle_closer(const handle_closer &);
  handle_closer &operator=(const handle_closer &);

 public:
  explicit handle_closer(void *handle) : handle_(handle) {}
  ~handle_closer() { close_handle(handle_); }
};

class eventlog_handle_closer {
  void *handle_;
  eventlog_handle_closer(const handle_closer &);
  eventlog_handle_closer &operator=(const eventlog_handle_closer &);

 public:
  explicit eventlog_handle_closer(void *handle) : handle_(handle) {}
  ~eventlog_handle_closer() { CloseEventLog(handle_); }
};

class c_heap_deleter {
 public:
  explicit c_heap_deleter(std::size_t size) : m_buf(::malloc(size)) {}

  ~c_heap_deleter() {
    if (m_buf) ::free(m_buf);
  }

  void realloc_mem(std::size_t num_bytes) {
    void *oldBuf = m_buf;
    m_buf = ::realloc(m_buf, num_bytes);
    if (!m_buf) {
      free(oldBuf);
    }
  }

  void *get() const { return m_buf; }

 private:
  void *m_buf;
};

template <class CharT>
struct winapi_traits;

template <>
struct winapi_traits<char> {
  static int cmp(const char *a, const char *b) { return std::strcmp(a, b); }
};

template <>
struct winapi_traits<wchar_t> {
  static int cmp(const wchar_t *a, const wchar_t *b) {
    return std::wcscmp(a, b);
  }
};

// Loop through the buffer and obtain the contents of the
// requested record in the buffer.
template <class CharT>
inline static bool find_record_in_buffer(
    const void *pBuffer, unsigned long dwBytesRead, const CharT *provider_name,
    unsigned int id_to_find, interprocess_eventlogrecord *&pevent_log_record) {
  const unsigned char *pRecord = static_cast<const unsigned char *>(pBuffer);
  const unsigned char *pEndOfRecords = pRecord + dwBytesRead;

  while (pRecord < pEndOfRecords) {
    interprocess_eventlogrecord *pTypedRecord =
        (interprocess_eventlogrecord *)(void *)pRecord;
    // Check provider, written at the end of the fixed-part of the record

    if (0 ==
        winapi_traits<CharT>::cmp(
            provider_name,
            (CharT *)(void *)(pRecord + sizeof(interprocess_eventlogrecord)))) {
      // Check event id
      if (id_to_find == (pTypedRecord->EventID & 0xFFFF)) {
        pevent_log_record = pTypedRecord;
        return true;
      }
    }

    pRecord += pTypedRecord->Length;
  }
  pevent_log_record = 0;
  return false;
}

// Obtains the bootup time from the System Event Log,
// event ID == 6005 (event log started).
// Adapted from
// http://msdn.microsoft.com/en-us/library/windows/desktop/bb427356.aspx
inline static bool get_last_bootup_time(std::wstring &stamp) {
  const wchar_t *source_name = L"System";
  const wchar_t *provider_name = L"EventLog";
  const unsigned short event_id = 6005u;

  unsigned long status = 0;
  unsigned long dwBytesToRead = 0;
  unsigned long dwBytesRead = 0;
  unsigned long dwMinimumBytesToRead = 0;

  // The source name (provider) must exist as a subkey of Application.
  void *hEventLog = OpenEventLogW(0, source_name);
  if (hEventLog) {
    eventlog_handle_closer hnd_closer(hEventLog);
    (void)hnd_closer;
    // Allocate an initial block of memory used to read event records. The
    // number of records read into the buffer will vary depending on the size of
    // each event. The size of each event will vary based on the size of the
    // user-defined data included with each event, the number and length of
    // insertion strings, and other data appended to the end of the event
    // record.
    dwBytesToRead = max_record_buffer_size;
    c_heap_deleter heap_deleter(dwBytesToRead);

    // Read blocks of records until you reach the end of the log or an
    // error occurs. The records are read from newest to oldest. If the buffer
    // is not big enough to hold a complete event record, reallocate the buffer.
    if (heap_deleter.get() != 0) {
      while (0 == status) {
        if (!ReadEventLogW(hEventLog,
                           eventlog_sequential_read | eventlog_backwards_read,
                           0, heap_deleter.get(), dwBytesToRead, &dwBytesRead,
                           &dwMinimumBytesToRead)) {
          status = get_last_error();
          if (error_insufficient_buffer == status) {
            status = 0;
            dwBytesToRead = dwMinimumBytesToRead;
            heap_deleter.realloc_mem(dwMinimumBytesToRead);
            if (!heap_deleter.get()) {
              return false;
            }
          } else {  // Not found or EOF
            return false;
          }
        } else {
          interprocess_eventlogrecord *pTypedRecord;
          // Print the contents of each record in the buffer.
          if (find_record_in_buffer(heap_deleter.get(), dwBytesRead,
                                    provider_name, event_id, pTypedRecord)) {
            wchar_t stamp_str[sizeof(unsigned long) * 3 + 1];
            std::swprintf(&stamp_str[0], L"%u",
                          ((unsigned int)pTypedRecord->TimeGenerated));
            stamp = stamp_str;
            break;
          }
        }
      }
    }
  }
  return true;
}
}  // namespace

extern "C" int boost_get_last_bootup_time(uint8_t *buffer, uint32_t max_length,
                                          uint32_t *real_length) {
  std::wstring ws;
  if (get_last_bootup_time(ws)) {
    const int bufferSize = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                               nullptr, 0, nullptr, nullptr);

    if (bufferSize <= max_length) {
      WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                          reinterpret_cast<char *>(buffer), bufferSize, nullptr,
                          nullptr);
      *real_length = bufferSize;
      return 0;
    } else {
      return -1;
    }
  }
}