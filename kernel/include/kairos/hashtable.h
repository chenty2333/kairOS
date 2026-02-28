/**
 * kernel/include/kairos/hashtable.h - Intrusive hash table helpers
 */

#ifndef _KAIROS_HASHTABLE_H
#define _KAIROS_HASHTABLE_H

#include <kairos/hash.h>
#include <kairos/list.h>

/*
 * Intrusive hash table:
 * - Callers embed struct list_head in their node type.
 * - Callers provide locking; this API is intentionally lock-free by design.
 * - Bucket count must be a power of two.
 */
#define KHASH_DECLARE(name, bits)                                              \
    _Static_assert((bits) < (sizeof(size_t) * 8U),                             \
                   "khash bits too large");                                    \
    struct list_head name[(size_t)1ULL << (bits)]

struct khash_stats {
    size_t bucket_count;
    size_t used_buckets;
    size_t entries;
    size_t max_bucket_depth;
};

#define KHASH_ARRAY_SIZE(table)                                                \
    (ARRAY_SIZE(table) +                                                       \
     0U * sizeof(char[1 - 2 * __builtin_types_compatible_p(                   \
                      typeof(table), typeof(&(table)[0]))]))

static inline bool khash_bucket_count_valid(size_t bucket_count) {
    return bucket_count != 0 &&
           (bucket_count & (bucket_count - (size_t)1U)) == 0;
}

static inline void khash_init(struct list_head *table, size_t bucket_count) {
    if (!table || !khash_bucket_count_valid(bucket_count))
        return;
    for (size_t i = 0; i < bucket_count; i++)
        INIT_LIST_HEAD(&table[i]);
}

static inline size_t khash_index_u64(uint64_t key, size_t bucket_count) {
    if (!khash_bucket_count_valid(bucket_count))
        return 0;
    return (size_t)(khash_mix64(key) & (uint64_t)(bucket_count - 1U));
}

static inline size_t khash_index_u32(uint32_t key, size_t bucket_count) {
    return khash_index_u64((uint64_t)key, bucket_count);
}

static inline void khash_add_u64(struct list_head *table, size_t bucket_count,
                                 struct list_head *node, uint64_t key) {
    if (!table || !node || !khash_bucket_count_valid(bucket_count))
        return;
    list_add_tail(node, &table[khash_index_u64(key, bucket_count)]);
}

static inline void khash_del(struct list_head *node) {
    if (!node)
        return;
    list_del(node);
    INIT_LIST_HEAD(node);
}

static inline void khash_stats_collect(const struct list_head *table,
                                       size_t bucket_count,
                                       struct khash_stats *out) {
    if (!out)
        return;

    out->bucket_count = bucket_count;
    out->used_buckets = 0;
    out->entries = 0;
    out->max_bucket_depth = 0;

    if (!table || !khash_bucket_count_valid(bucket_count))
        return;

    for (size_t i = 0; i < bucket_count; i++) {
        const struct list_head *head = &table[i];
        size_t depth = 0;
        for (const struct list_head *pos = head->next; pos != head;
             pos = pos->next) {
            depth++;
        }
        if (depth == 0)
            continue;

        out->used_buckets++;
        out->entries += depth;
        if (depth > out->max_bucket_depth)
            out->max_bucket_depth = depth;
    }
}

static inline size_t khash_collision_entries(const struct khash_stats *stats) {
    if (!stats || stats->entries <= stats->used_buckets)
        return 0;
    return stats->entries - stats->used_buckets;
}

static inline uint32_t khash_load_factor_per_mille(
    const struct khash_stats *stats) {
    if (!stats || stats->bucket_count == 0)
        return 0;
    return (uint32_t)(((uint64_t)stats->entries * 1000ULL) /
                      (uint64_t)stats->bucket_count);
}

static inline uint32_t khash_avg_chain_per_mille(const struct khash_stats *stats) {
    if (!stats || stats->used_buckets == 0)
        return 0;
    return (uint32_t)(((uint64_t)stats->entries * 1000ULL) /
                      (uint64_t)stats->used_buckets);
}

static inline bool
khash_rehash_recommended_default(const struct khash_stats *stats) {
    if (!stats || stats->bucket_count == 0)
        return false;
    if (khash_load_factor_per_mille(stats) > 2000U)
        return true;
    if (stats->max_bucket_depth >= 8U)
        return true;
    return false;
}

#define KHASH_INIT(table) khash_init((table), KHASH_ARRAY_SIZE(table))
#define KHASH_BUCKET_U64(table, key)                                           \
    khash_index_u64((uint64_t)(key), KHASH_ARRAY_SIZE(table))
#define KHASH_BUCKET_U32(table, key)                                           \
    khash_index_u32((uint32_t)(key), KHASH_ARRAY_SIZE(table))
#define KHASH_HEAD_U64(table, key) (&(table)[KHASH_BUCKET_U64((table), (key))])
#define KHASH_HEAD_U32(table, key) (&(table)[KHASH_BUCKET_U32((table), (key))])
#define KHASH_STATS(table, out_stats)                                          \
    khash_stats_collect((table), KHASH_ARRAY_SIZE(table), (out_stats))

#define KHASH_FOR_EACH_POSSIBLE_U64(pos, table, key, member)                  \
    list_for_each_entry(pos, KHASH_HEAD_U64((table), (key)), member)
#define KHASH_FOR_EACH_POSSIBLE_U32(pos, table, key, member)                  \
    list_for_each_entry(pos, KHASH_HEAD_U32((table), (key)), member)

/* API aliases for subsystem call sites */
#define khash_bucket(key, bits)                                                \
    khash_index_u64((uint64_t)(key), (size_t)1ULL << (bits))
#define khash_add(table, node, key_u64)                                        \
    khash_add_u64((table), KHASH_ARRAY_SIZE(table), (node),                    \
                  (uint64_t)(key_u64))
#define khash_for_each_possible(table, pos, member, key_u64)                   \
    KHASH_FOR_EACH_POSSIBLE_U64((pos), (table), (key_u64), member)
#define khash_for_each_possible_u32(table, pos, member, key_u32)               \
    KHASH_FOR_EACH_POSSIBLE_U32((pos), (table), (key_u32), member)

#endif
