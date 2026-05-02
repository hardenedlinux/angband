"""Slab cache probing and analysis for kernel heap exploitation.

Provides tools to probe slab cache sizes, object counts, and allocator
configuration on a target kernel. Used by exploit generators to determine
correct spray sizes and target caches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


KNOWN_KMALLOC_CACHES = [
    "kmalloc-8", "kmalloc-16", "kmalloc-32", "kmalloc-64",
    "kmalloc-96", "kmalloc-128", "kmalloc-192", "kmalloc-256",
    "kmalloc-512", "kmalloc-1k", "kmalloc-2k", "kmalloc-4k",
    "kmalloc-8k",
]

SIZE_TO_CACHE = {
    8:     "kmalloc-8",
    16:    "kmalloc-16",
    32:    "kmalloc-32",
    64:    "kmalloc-64",
    96:    "kmalloc-96",
    128:   "kmalloc-128",
    192:   "kmalloc-192",
    256:   "kmalloc-256",
    512:   "kmalloc-512",
    1024:  "kmalloc-1k",
    2048:  "kmalloc-2k",
    4096:  "kmalloc-4k",
    8192:  "kmalloc-8k",
}


def object_size_to_cache(size: int) -> str:
    """Map an object's allocation size to the nearest kmalloc cache.

    Consolidates multiple caches: objects <= 96 bytes may land in kmalloc-96
    due to slab merging under CONFIG_SLAB_MERGE_DEFAULT, but we report the
    standard theoretical cache. The exploit template should verify empirically.
    """
    for threshold, cache in sorted(SIZE_TO_CACHE.items()):
        if size <= threshold:
            return cache
    return "kmalloc-8k"


def estimate_spray_count(cache_name: str) -> int:
    """Return a recommended spray count for a given slab cache.

    Smaller caches hold more objects per slab page, so need more spray
    to fill and force a new slab page allocation.
    """
    if "4k" in cache_name or "8k" in cache_name:
        return 64    # 4-8 objects per slab
    if "2k" in cache_name:
        return 128   # ~16 objects per slab
    if "1k" in cache_name:
        return 192   # ~16 objects per slab
    if "512" in cache_name:
        return 256   # ~32 objects per slab
    if "256" in cache_name:
        return 256   # ~32 objects per slab
    if "192" in cache_name:
        return 256
    return 256


def spray_size_for_cache(cache_name: str) -> int:
    """Return the user-data size for a msg_msg spray targeting a given cache.

    msg_msg header is 48 bytes on x86_64. To land in cache X, we need:
    total_size = 48 + data_size <= X
    """
    cache_sizes = {
        "kmalloc-32":   32,  "kmalloc-64":   64,  "kmalloc-96":   96,
        "kmalloc-128": 128,  "kmalloc-192": 192,  "kmalloc-256": 256,
        "kmalloc-512": 512,  "kmalloc-1k": 1024, "kmalloc-2k":  2048,
        "kmalloc-4k": 4096,  "kmalloc-8k": 8192,
    }
    cache_max = cache_sizes.get(cache_name, 256)
    data_size = cache_max - 48  # msg_msg header
    if data_size < 0:
        return 0
    return data_size


@dataclass
class SlabProbe:
    """Information about a target slab cache from the guest kernel."""

    cache_name: str = ""
    object_size: int = 0
    active_objs: int = 0
    num_objs: int = 0
    slabs: int = 0
    objects_per_slab: int = 0
    page_order: int = 0

    @property
    def estimated_total_objects(self) -> int:
        """Total objects (allocated + free) in this cache."""
        if self.objects_per_slab > 0 and self.slabs > 0:
            return self.objects_per_slab * self.slabs
        return self.num_objs

    @property
    def free_objects_estimate(self) -> int:
        """Estimated free objects in this cache."""
        return max(0, self.estimated_total_objects - self.active_objs)

    def to_dict(self) -> dict:
        return {
            "cache_name": self.cache_name,
            "object_size": self.object_size,
            "active_objs": self.active_objs,
            "num_objs": self.num_objs,
            "slabs": self.slabs,
            "objects_per_slab": self.objects_per_slab,
            "page_order": self.page_order,
        }


def parse_slabinfo_line(line: str) -> Optional[SlabProbe]:
    """Parse one line from /proc/slabinfo into a SlabProbe."""
    parts = line.split()
    if len(parts) < 9:
        return None

    try:
        probe = SlabProbe(
            cache_name=parts[0],
            active_objs=int(parts[1]),
            num_objs=int(parts[2]),
            object_size=int(parts[3]),
            objects_per_slab=int(parts[4]),
            slabs=int(parts[7]),
            page_order=0,
        )
        return probe
    except (ValueError, IndexError):
        return None


def parse_slabinfo(raw: str) -> dict[str, SlabProbe]:
    """Parse full /proc/slabinfo output into a dict of SlabProbe objects."""
    results = {}
    for line in raw.splitlines():
        probe = parse_slabinfo_line(line)
        if probe:
            results[probe.cache_name] = probe
    return results


def find_best_kmalloc_cache(
    slabinfo: dict[str, SlabProbe],
    target_object_size: int,
) -> tuple[Optional[str], Optional[int]]:
    """Find the kmalloc cache that best fits a target object size.

    Returns (cache_name, object_size_in_cache) or (None, None).
    Considers slab merging: small caches may be merged into larger ones.
    """
    predicted = object_size_to_cache(target_object_size)

    if predicted in slabinfo:
        return predicted, slabinfo[predicted].object_size

    for cache_name in KNOWN_KMALLOC_CACHES:
        if cache_name in slabinfo:
            obj_size = slabinfo[cache_name].object_size
            if obj_size >= target_object_size:
                return cache_name, obj_size

    return None, None


def detect_random_kmalloc_caches(
    slabinfo: dict[str, SlabProbe],
) -> tuple[bool, int]:
    """Detect CONFIG_RANDOM_KMALLOC_CACHES mitigation.

    When enabled, the kernel creates multiple randomized kmalloc clones
    (e.g., kmalloc-rnd-01-4k through kmalloc-rnd-15-4k).  Each kmalloc()
    call is hashed to one of these caches based on caller address + seed,
    making same-cache heap grooming unreliable.

    Returns (is_enabled, number_of_clones).
    """
    rnd_count = 0
    for name in slabinfo:
        if name.startswith("kmalloc-rnd-"):
            rnd_count += 1
    # If any kmalloc-rnd-* caches exist, the mitigation is active
    is_enabled = rnd_count > 0
    return is_enabled, rnd_count


def random_cache_name(base_cache: str, index: int) -> str:
    """Generate a kmalloc-rnd-XX-* cache name."""
    parts = base_cache.split("-", 1)
    if len(parts) == 2:
        return f"kmalloc-rnd-{index:02d}-{parts[1]}"
    return f"kmalloc-rnd-{index:02d}"
