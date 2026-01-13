#pragma once
#include <cstdint>
#include "hooker/hooker.h"


inline uint8_t nops[] = { 0xC3 };                  // nop stub
inline uint8_t retfs[] = { 0x48, 0x31, 0xC0, 0xC3 }; // return false stub
inline uint8_t retts[] = { 0xB0, 0x01, 0xC3 };      // return true stub


inline hooker::hook_t r1{}, r2{}, r3{}; // referre
inline hooker::hook_t fly{}; // flying
inline hooker::hook_t nc{}; // no gun cooldown
inline hooker::hook_t dv{}; // developer
inline hooker::hook_t ssl{}; // ssl
inline hooker::hook_t c1{}, c2{}, c3{}, c4{}, c5{}; // clothing unlock
inline hooker::hook_t q1{}, q2{}, q3{}, q4{}, q5{}; // game quits
inline hooker::hook_t v1{}, v2{}, v3{}, v4{}, v5{}, v6{}, v7{}; // item/inv/key unlocker