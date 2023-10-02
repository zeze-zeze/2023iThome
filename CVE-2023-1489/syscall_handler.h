#pragma once
#include "ia32.hpp"

extern "C" std::uint32_t m_kpcr_rsp_offset;
extern "C" std::uint32_t m_kpcr_krsp_offset;

extern "C" std::uintptr_t m_pop_rcx_gadget;
extern "C" std::uintptr_t m_mov_cr4_gadget;
extern "C" std::uintptr_t m_sysret_gadget;

extern "C" cr4 m_smep_on;
extern "C" cr4 m_smep_off;
extern "C" std::uintptr_t m_system_call;
extern "C" void syscall_wrapper(...);