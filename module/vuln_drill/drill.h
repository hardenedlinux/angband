#ifndef _VULN_DRILL_H
#define _VULN_DRILL_H

/*
 * vuln_drill -- CTF-style vulnerable kernel module for Angband
 *
 * Modeled after kernel-hack-drill by Alexander Popov.
 *
 * Interface: /proc/vuln_drill_act (write-only)
 *   Write a string "ACT ITEM [VAL OFFSET]" to perform an action.
 *
 * Actions:
 *   ALLOC    <item>               -- allocate item N (kmalloc DRILL_ITEM_SIZE)
 *   CALLBACK <item>               -- invoke item->callback()
 *   WRITE    <item> <val> <off>   -- write val at item->data[off]
 *   FREE     <item>               -- kfree(item) WITHOUT nulling pointer
 *   RESET    <item>               -- set item pointer to NULL
 *   READ     <item> <off>         -- read val from item->data[off]
 *                                    (result in /proc/vuln_drill read_val)
 *
 * Vulnerabilities:
 *   1. DRILL_ACT_FREE does not null the pointer -> UAF
 *   2. DRILL_ACT_CALLBACK does not check if item is freed -> UAF callback
 *   3. DRILL_ACT_WRITE does not bounds-check offset -> OOB write
 *   4. DRILL_ACT_READ does not bounds-check offset -> OOB read (infoleak)
 */

/* Buffer size for the act string: "act item val offset\0" */
#define DRILL_ACT_SIZE 59

	/* Actions */
enum drill_act_t {
	DRILL_ACT_NONE       = 0,
	DRILL_ACT_ALLOC      = 1,
	DRILL_ACT_CALLBACK   = 2,
	DRILL_ACT_WRITE      = 3,
	DRILL_ACT_FREE       = 4,
	DRILL_ACT_RESET      = 5,
	DRILL_ACT_READ       = 6,
	DRILL_ACT_ALLOC_4K   = 7,  /* allocate kmalloc-4k object */
	DRILL_ACT_KWRITE_INC = 8,  /* increment *((ulong*)(item->data[0..7]) + off) */
};

/*
 * Item size: 95 bytes -> kmalloc-96 on kernels with fine-grained caches,
 * or kmalloc-128 on older kernels.
 *
 * struct drill_item_t layout:
 *   [0..7]   foobar      (8 bytes)
 *   [8..15]  callback    (8 bytes, function pointer)
 *   [16..94] data[]      (79 bytes, flexible array)
 */
#define DRILL_ITEM_SIZE 95

struct drill_item_t {
	unsigned long foobar;
	void (*callback)(void);
	char data[];   /* C99 flexible array member */
};

/* Maximum number of items */
#define DRILL_N 10240

#endif /* _VULN_DRILL_H */
