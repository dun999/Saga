#pragma once
// Saga's memory layer over Walrus Memory. Writes are queued and tracked in the background
// until the relayer reports the Walrus blob id; reads are semantic recalls. There is no local
// database: the in-process state here is a bounded cache for sharing recent writes.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "memwal/client.h"
#include "memwal/namespaces.h"

namespace saga::memwal {

struct WriteRecord {
  std::string ns, kind, text, job_id, blob_id, status = "queued", error;
  std::string ref;         // what this write belongs to, for the UI ("<turn>" or "<turn>:<step>")
  std::string owner;       // uid whose turn produced a write to a shared namespace ("" = no user content)
  int64_t ts = 0;
  int attempts = 0;        // transient relayer failures are retried with backoff
  int64_t retry_at = 0;    // unix seconds; 0 = now
  std::chrono::steady_clock::time_point submitted{};  // when the relayer took the job
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
  bool put(const std::string& ns, const std::string& kind, const std::string& text, const std::string& ref = "",
           const std::string& owner = "");
  // One capture path for agent facts, user corrections, and handoff summaries. Stable content IDs
  // deduplicate proposals, and queued records are immediately available to every agent of this user.
  json remember(const std::string& uid, const std::string& text, const std::string& kind = "fact",
                const std::string& agent = "", const std::string& session = "", const std::string& ref = "");
  std::vector<Memory> local_memories(const std::string& ns) const;
  // Fallback for relayers without namespace listing; old agents' lessons remain shared on recall.
  void legacy_agents(const std::vector<std::string>& names);
  // Semantic recall; errors are logged and yield an empty result so a relayer hiccup
  // degrades the assistant instead of breaking the turn.
  // `failed` (optional) tells an error apart from "nothing matched".
  std::vector<Memory> recall(const std::string& query, const std::string& ns, const RecallOptions& opt = {},
                             bool* failed = nullptr);

  void add_listener(WriteListener fn);
  std::vector<WriteRecord> recent(size_t n = 50) const;
  size_t blobs_written() const { return blobs_written_; }
  void flush(std::chrono::seconds timeout);  // wait for queued writes (CLI commands, tests)

 private:
  void worker();
  // A transient failure (relayer or SEAL backend briefly down) goes back on the queue instead of
  // being dropped. Returns false once the write has used its attempts or the error is permanent.
  bool retry_later(WriteRecord& r);
  void notify(const WriteRecord& r);
  std::vector<Memory> recall_one(const std::string& query, const std::string& ns, const RecallOptions& opt,
                                 bool* failed);
  std::vector<std::string> legacy_namespaces(const std::string& uid);
  void update_local(const WriteRecord& r);  // caller holds mu_

  struct Recalled {
    std::vector<Memory> hits;
    bool failed = false;
  };

  Client* client_;
  bool enabled_;
  mutable std::mutex mu_;
  std::map<std::string, std::shared_future<Recalled>> recalls_;  // reads in flight, by request
  std::once_flag namespaces_loaded_;
  std::optional<std::set<std::string>> namespaces_;
  std::set<std::string> legacy_agents_;
  // Bounded across the deployment, including writes in the worker's submitting phase. Confirmed
  // entries stay until evicted; failed entries are removed immediately.
  std::deque<std::pair<std::string, Memory>> local_;
  std::condition_variable cv_;
  std::deque<WriteRecord> queue_;       // not yet submitted
  size_t submitting_ = 0;               // taken off queue_, request to the relayer not finished yet
  std::vector<WriteRecord> log_;        // submitted this session
  std::vector<WriteListener> listeners_;
  std::atomic<size_t> blobs_written_{0};
  std::atomic<bool> stop_{false};
  std::atomic<int> flushing_{0};  // callers waiting in flush()
  std::thread thread_;
};

}  // namespace saga::memwal
