#pragma once
#include "config.hpp"
#include <deque>
#include <mutex>
#include <cstring>
namespace vpn {
inline std::mutex event_mutex;
inline std::deque<std::string> core_events;
inline uint64_t dropped_events=0;
inline void reset_events(){std::lock_guard<std::mutex> lock(event_mutex);core_events.clear();dropped_events=0;}
inline void publish_event(Json event){std::lock_guard<std::mutex> lock(event_mutex);if(core_events.size()==256){core_events.pop_front();++dropped_events;}event["dropped_before"]=Json::integer(dropped_events);core_events.push_back(json_dump(event));}
inline int read_event(char* output,uint32_t capacity){std::lock_guard<std::mutex> lock(event_mutex);if(core_events.empty())return 0;auto& text=core_events.front();if(!output||capacity<=text.size())return -int(text.size()+1);std::memcpy(output,text.data(),text.size());output[text.size()]=0;auto n=int(text.size());core_events.pop_front();return n;}
}
