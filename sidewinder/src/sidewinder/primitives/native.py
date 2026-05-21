"""CFFI bindings for the native C primitives."""

import os
import ctypes
import ctypes.util
from pathlib import Path


_lib: ctypes.CDLL | None = None
_loaded = False


def _find_lib() -> str | None:
    search_paths = [
        Path(__file__).parent.parent.parent.parent / "c_primitives" / "libsidewinder.so",
        Path("c_primitives/libsidewinder.so"),
        Path("libsidewinder.so"),
    ]
    for p in search_paths:
        resolved = p.resolve()
        if resolved.exists():
            return str(resolved)

    found = ctypes.util.find_library("sidewinder")
    if found:
        return found
    return None


def load() -> ctypes.CDLL:
    global _lib, _loaded
    if _loaded and _lib is not None:
        return _lib

    lib_path = _find_lib()
    if lib_path is None:
        lib_path = os.environ.get("SIDEWINDER_LIB_PATH", "")
        if not os.path.exists(lib_path):
            raise RuntimeError(
                "Cannot find libsidewinder.so. Build it with: make -C c_primitives"
            )

    _lib = ctypes.CDLL(lib_path)

    _lib.sw_flush_line.argtypes = [ctypes.c_void_p]
    _lib.sw_flush_line.restype = None

    _lib.sw_flush_range.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _lib.sw_flush_range.restype = None

    _lib.sw_mfence.argtypes = []
    _lib.sw_mfence.restype = None

    _lib.sw_lfence.argtypes = []
    _lib.sw_lfence.restype = None

    _lib.sw_reload_line.argtypes = [ctypes.c_void_p]
    _lib.sw_reload_line.restype = ctypes.c_uint64

    _lib.sw_probe_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    _lib.sw_probe_set.restype = ctypes.c_int

    _lib.sw_prime_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    _lib.sw_prime_set.restype = None

    _lib.sw_evict_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    _lib.sw_evict_set.restype = None

    _lib.sw_cache_calibrate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    _lib.sw_cache_calibrate.restype = ctypes.c_uint64

    _lib.sw_flush_reload.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    _lib.sw_flush_reload.restype = ctypes.c_uint64

    _lib.sw_evict_buffer.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _lib.sw_evict_buffer.restype = None

    _lib.sw_rdtsc.argtypes = []
    _lib.sw_rdtsc.restype = ctypes.c_uint64

    _lib.sw_rdtscp.argtypes = []
    _lib.sw_rdtscp.restype = ctypes.c_uint64

    _lib.sw_rdtsc_begin.argtypes = []
    _lib.sw_rdtsc_begin.restype = ctypes.c_uint64

    _lib.sw_rdtsc_end.argtypes = []
    _lib.sw_rdtsc_end.restype = ctypes.c_uint64

    _lib.sw_timer_calibrate.argtypes = []
    _lib.sw_timer_calibrate.restype = ctypes.c_uint64

    _lib.sw_virt_to_phys.argtypes = [ctypes.c_void_p]
    _lib.sw_virt_to_phys.restype = ctypes.c_uint64

    _lib.sw_get_cache_info.argtypes = [ctypes.c_void_p]
    _lib.sw_get_cache_info.restype = ctypes.c_int

    _lib.sw_get_hugepage_info.argtypes = [ctypes.c_void_p]
    _lib.sw_get_hugepage_info.restype = ctypes.c_int

    _lib.sw_pin_to_core.argtypes = [ctypes.c_int]
    _lib.sw_pin_to_core.restype = None

    _lib.sw_hammer_classic.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    _lib.sw_hammer_classic.restype = None

    _lib.sw_hammer_frequency.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
                                         ctypes.c_void_p, ctypes.c_int]
    _lib.sw_hammer_frequency.restype = None

    _lib.sw_hammer_many_sided.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
                                          ctypes.c_uint64, ctypes.c_int]
    _lib.sw_hammer_many_sided.restype = None

    _lib.sw_check_flips.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    _lib.sw_check_flips.restype = ctypes.c_int

    _lib.sw_refresh_interval_measure.argtypes = []
    _lib.sw_refresh_interval_measure.restype = ctypes.c_double

    _lib.sw_generate_freq_patterns.argtypes = [ctypes.c_void_p, ctypes.c_int]
    _lib.sw_generate_freq_patterns.restype = None

    _lib.sw_alloc_huge_pages.argtypes = [ctypes.c_int]
    _lib.sw_alloc_huge_pages.restype = ctypes.c_int

    _lib.sw_map_huge_region.argtypes = [ctypes.c_size_t]
    _lib.sw_map_huge_region.restype = ctypes.c_void_p

    _lib.sw_free_huge_region.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _lib.sw_free_huge_region.restype = None

    _lib.sw_tsa_probe_sq.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_void_p]
    _lib.sw_tsa_probe_sq.restype = ctypes.c_int

    _lib.sw_ghostrace_probe.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                         ctypes.c_int, ctypes.c_void_p]
    _lib.sw_ghostrace_probe.restype = ctypes.c_int

    _lib.sw_bhi_probe.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_void_p]
    _lib.sw_bhi_probe.restype = ctypes.c_int

    _lib.sw_prefetch_kaslr_probe.argtypes = [ctypes.c_uint64, ctypes.c_int]
    _lib.sw_prefetch_kaslr_probe.restype = ctypes.c_uint64

    _lib.sw_pte_spray.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p]
    _lib.sw_pte_spray.restype = ctypes.c_int

    _lib.sw_kernel_write_via_pte.argtypes = [ctypes.c_uint64, ctypes.c_uint64,
                                               ctypes.c_char_p, ctypes.c_size_t]
    _lib.sw_kernel_write_via_pte.restype = ctypes.c_int

    _lib.sw_ssb_probe.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_void_p]
    _lib.sw_ssb_probe.restype = ctypes.c_int

    _lib.sw_itlb_multihit_probe.argtypes = [ctypes.c_int, ctypes.c_void_p]
    _lib.sw_itlb_multihit_probe.restype = ctypes.c_int

    _lib.sw_spectre_v1_probe.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                         ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _lib.sw_spectre_v1_probe.restype = ctypes.c_int

    _lib.sw_spy_run_attack.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    _lib.sw_spy_run_attack.restype = ctypes.c_int

    _lib.sw_find_ptes_in_spray.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    _lib.sw_find_ptes_in_spray.restype = ctypes.c_int

    _lib.sw_targeted_pte_flip.argtypes = [ctypes.c_uint64, ctypes.c_void_p,
                                           ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    _lib.sw_targeted_pte_flip.restype = ctypes.c_int

    _lib.sw_overwrite_kernel_page.argtypes = [ctypes.c_uint64, ctypes.c_char_p,
                                               ctypes.c_size_t]
    _lib.sw_overwrite_kernel_page.restype = ctypes.c_int

    _lib.sw_trigger_modprobe_exec.argtypes = []
    _lib.sw_trigger_modprobe_exec.restype = ctypes.c_int

    _lib.sw_vmscape_probe.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_void_p]
    _lib.sw_vmscape_probe.restype = ctypes.c_int

    _lib.sw_vmscape_exfiltrate.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                            ctypes.c_void_p, ctypes.c_int,
                                            ctypes.c_int, ctypes.c_int]
    _lib.sw_vmscape_exfiltrate.restype = ctypes.c_int

    _lib.sw_l1tf_probe.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                    ctypes.c_int, ctypes.c_void_p]
    _lib.sw_l1tf_probe.restype = ctypes.c_int

    _lib.sw_mds_probe.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_void_p]
    _lib.sw_mds_probe.restype = ctypes.c_int

    _lib.sw_hertzbleed_probe.argtypes = [ctypes.c_int, ctypes.c_void_p]
    _lib.sw_hertzbleed_probe.restype = ctypes.c_int

    _lib.sw_hertzbleed_calibrate_threshold.argtypes = []
    _lib.sw_hertzbleed_calibrate_threshold.restype = ctypes.c_int

    _lib.sw_zenhammer_hammer.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
                                         ctypes.c_int, ctypes.c_int, ctypes.c_int]
    _lib.sw_zenhammer_hammer.restype = None

    _loaded = True
    return _lib


def get_lib() -> ctypes.CDLL:
    return load()
