#pragma once
#include <deque>
#include <string>

namespace saga::web {
// A slow or disconnected browser must not retain an unlimited producer stream.
class EventQueue {
 public:
  explicit EventQueue(size_t max_bytes = 2 * 1024 * 1024) : max_bytes_(max_bytes) {}
  bool push(std::string line) {
    if (lines_.size() >= 4096 || line.size() > max_bytes_ - bytes_) return false;
    bytes_ += line.size();
    lines_.push_back(std::move(line));
    return true;
  }
  std::string pop() {
    std::string line = std::move(lines_.front());
    lines_.pop_front();
    bytes_ -= line.size();
    return line;
  }
  bool empty() const { return lines_.empty(); }
  size_t bytes() const { return bytes_; }
  void clear() { lines_.clear(); bytes_ = 0; }
 private:
  size_t max_bytes_, bytes_ = 0;
  std::deque<std::string> lines_;
};
}  // namespace saga::web
