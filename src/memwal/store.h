#pragma once
// Saga's memory layer over Walrus Memory. Writes are queued and tracked in the background
// until the relayer reports the Walrus blob id; reads are semantic recalls. There is no local
// database: the in-process state here is only a cache of what is in flight this session.
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "memwal/client.h"

namespace saga::memwal {

struct WriteRecord {
  std::string ns, kind, text, job_id, blob_id, status = "queued", error;
  int64_t ts = 0;
  json to_json() const;
};

using WriteListener = std::function<void(const WriteRecord&)>;

// Structured records are stored as "SAGA:<kind> <json>" so they stay human-readable in
// the Walrus blob and are still embedded meaningfully by the relayer.
std::string encode_record(const std::string& kind, const json& payload);
std::optional<json> decode_record(const std::string& text, const std::string& kind);

class Store {
 public:
  Store(Client* client, bool enabled);
  ~Store();

  bool enabled() const { return enabled_ && client_; }
  Client* client() const { return client_; }

  // Queue a memory. Returns immediately; listener fires on status changes.
  void put(const std::string& ns, const std::string& kind, const std::string& text);
  // Server-side fact extraction (relayer LLM), one memory per extracted fact.
  void analyze(const std::string& ns, const std::string& text);
  // Semantic recall; errors are logged and yield an empty result so a relayer hiccup
  // degrades the assistant instead of breaking the turn.
  std::vector<Memory> recall(const std::string& query, const std::string& ns, const RecallOptions& opt = {});

  void add_listener(WriteListener fn);
  std::vector<WriteRecord> recent(size_t n = 50) const;
  size_t blobs_written() const { return blobs_written_; }
  void flush(std::chrono::seconds timeout);  // wait for queued writes (CLI commands, tests)

 private:
  void worker();
  void notify(const WriteRecord& r);

  Client* client_;
  bool enabled_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<WriteRecord> queue_;       // not yet submitted
  std::vector<WriteRecord> log_;        // submitted this session
  std::vector<WriteListener> listeners_;
  std::atomic<size_t> blobs_written_{0};
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

}  // namespace saga::memwal
