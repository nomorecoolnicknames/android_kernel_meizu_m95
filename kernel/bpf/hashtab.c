/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/bpf.h>
#include <linux/jhash.h>
#include <linux/filter.h>
#include <linux/vmalloc.h>
#include <linux/smp.h>

struct bpf_htab {
	struct bpf_map map;
	struct hlist_head *buckets;
	raw_spinlock_t lock;
	u32 count;	/* number of elements in this hashtable */
	u32 n_buckets;	/* number of hash buckets */
	u32 elem_size;	/* size of each element in bytes */
};

/* each htab element is struct htab_elem + key + value */
struct htab_elem {
	struct hlist_node hash_node;
	struct rcu_head rcu;
	u32 hash;
	char key[0] __aligned(8);
};

/* Called from syscall */
static struct bpf_map *htab_map_alloc(union bpf_attr *attr)
{
	struct bpf_htab *htab;
	int err, i;

	htab = kzalloc(sizeof(*htab), GFP_USER);
	if (!htab)
		return ERR_PTR(-ENOMEM);

	/* mandatory map attributes */
	htab->map.key_size = attr->key_size;
	htab->map.value_size = attr->value_size;
	htab->map.max_entries = attr->max_entries;

	/* check sanity of attributes.
	 * value_size == 0 may be allowed in the future to use map as a set
	 */
	err = -EINVAL;
	if (htab->map.max_entries == 0 || htab->map.key_size == 0 ||
	    htab->map.value_size == 0)
		goto free_htab;

	/* hash table size must be power of 2 */
	htab->n_buckets = roundup_pow_of_two(htab->map.max_entries);

	err = -E2BIG;
	if (htab->map.key_size > MAX_BPF_STACK)
		/* eBPF programs initialize keys on stack, so they cannot be
		 * larger than max stack size
		 */
		goto free_htab;

	if (htab->map.value_size >= (1 << (KMALLOC_SHIFT_MAX - 1)) -
	    MAX_BPF_STACK - sizeof(struct htab_elem))
		/* if value_size is bigger, the user space won't be able to
		 * access the elements via bpf syscall. This check also makes
		 * sure that the elem_size doesn't overflow and it's
		 * kmalloc-able later in htab_map_update_elem()
		 */
		goto free_htab;

	htab->elem_size = sizeof(struct htab_elem) +
			  round_up(htab->map.key_size, 8) +
			  htab->map.value_size;

	/* prevent zero size kmalloc and check for u32 overflow */
	if (htab->n_buckets == 0 ||
	    htab->n_buckets > U32_MAX / sizeof(struct hlist_head))
		goto free_htab;

	if ((u64) htab->n_buckets * sizeof(struct hlist_head) +
	    (u64) htab->elem_size * htab->map.max_entries >=
	    U32_MAX - PAGE_SIZE)
		/* make sure page count doesn't overflow */
		goto free_htab;

	htab->map.pages = round_up(htab->n_buckets * sizeof(struct hlist_head) +
				   htab->elem_size * htab->map.max_entries,
				   PAGE_SIZE) >> PAGE_SHIFT;

	err = -ENOMEM;
	htab->buckets = kmalloc_array(htab->n_buckets, sizeof(struct hlist_head),
				      GFP_USER | __GFP_NOWARN);

	if (!htab->buckets) {
		htab->buckets = vmalloc(htab->n_buckets * sizeof(struct hlist_head));
		if (!htab->buckets)
			goto free_htab;
	}

	for (i = 0; i < htab->n_buckets; i++)
		INIT_HLIST_HEAD(&htab->buckets[i]);

	raw_spin_lock_init(&htab->lock);
	htab->count = 0;

	return &htab->map;

free_htab:
	kfree(htab);
	return ERR_PTR(err);
}

static inline u32 htab_map_hash(const void *key, u32 key_len)
{
	return jhash(key, key_len, 0);
}

static inline struct hlist_head *select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &htab->buckets[hash & (htab->n_buckets - 1)];
}

static struct htab_elem *lookup_elem_raw(struct hlist_head *head, u32 hash,
					 void *key, u32 key_size)
{
	struct htab_elem *l;

	hlist_for_each_entry_rcu(l, head, hash_node)
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;

	return NULL;
}

/* Called from syscall or from eBPF program */
static void *htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_head *head;
	struct htab_elem *l;
	u32 hash, key_size;

	/* Must be called with rcu_read_lock. */
	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size);

	head = select_bucket(htab, hash);

	l = lookup_elem_raw(head, hash, key, key_size);

	if (l)
		return l->key + round_up(map->key_size, 8);

	return NULL;
}

/* Called from syscall */
static int htab_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_head *head;
	struct htab_elem *l, *next_l;
	u32 hash, key_size;
	int i;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size);

	head = select_bucket(htab, hash);

	/* lookup the key */
	l = lookup_elem_raw(head, hash, key, key_size);

	if (!l) {
		i = 0;
		goto find_first_elem;
	}

	/* key was found, get next key in the same bucket */
	next_l = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&l->hash_node)),
				  struct htab_elem, hash_node);

	if (next_l) {
		/* if next elem in this hash list is non-zero, just return it */
		memcpy(next_key, next_l->key, key_size);
		return 0;
	}

	/* no more elements in this hash list, go to the next bucket */
	i = hash & (htab->n_buckets - 1);
	i++;

find_first_elem:
	/* iterate over buckets */
	for (; i < htab->n_buckets; i++) {
		head = select_bucket(htab, i);

		/* pick first element in the bucket */
		next_l = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),
					  struct htab_elem, hash_node);
		if (next_l) {
			/* if it's not empty, just return it */
			memcpy(next_key, next_l->key, key_size);
			return 0;
		}
	}

	/* itereated over all buckets and all elements */
	return -ENOENT;
}

/* Called from syscall or from eBPF program */
static int htab_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct htab_elem *l_new, *l_old;
	struct hlist_head *head;
	unsigned long flags;
	u32 key_size;
	int ret;

	if (map_flags > BPF_EXIST)
		/* unknown flags */
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held());

	/* allocate new element outside of lock */
	l_new = kmalloc(htab->elem_size, GFP_ATOMIC | __GFP_NOWARN);
	if (!l_new)
		return -ENOMEM;

	key_size = map->key_size;

	memcpy(l_new->key, key, key_size);
	memcpy(l_new->key + round_up(key_size, 8), value, map->value_size);

	l_new->hash = htab_map_hash(l_new->key, key_size);

	/* bpf_map_update_elem() can be called in_irq() */
	raw_spin_lock_irqsave(&htab->lock, flags);

	head = select_bucket(htab, l_new->hash);

	l_old = lookup_elem_raw(head, l_new->hash, key, key_size);

	if (!l_old && unlikely(htab->count >= map->max_entries)) {
		/* if elem with this 'key' doesn't exist and we've reached
		 * max_entries limit, fail insertion of new elem
		 */
		ret = -E2BIG;
		goto err;
	}

	if (l_old && map_flags == BPF_NOEXIST) {
		/* elem already exists */
		ret = -EEXIST;
		goto err;
	}

	if (!l_old && map_flags == BPF_EXIST) {
		/* elem doesn't exist, cannot update it */
		ret = -ENOENT;
		goto err;
	}

	/* add new element to the head of the list, so that concurrent
	 * search will find it before old elem
	 */
	hlist_add_head_rcu(&l_new->hash_node, head);
	if (l_old) {
		hlist_del_rcu(&l_old->hash_node);
		kfree_rcu(l_old, rcu);
	} else {
		htab->count++;
	}
	raw_spin_unlock_irqrestore(&htab->lock, flags);

	return 0;
err:
	raw_spin_unlock_irqrestore(&htab->lock, flags);
	kfree(l_new);
	return ret;
}

/* Called from syscall or from eBPF program */
static int htab_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_head *head;
	struct htab_elem *l;
	unsigned long flags;
	u32 hash, key_size;
	int ret = -ENOENT;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size);

	raw_spin_lock_irqsave(&htab->lock, flags);

	head = select_bucket(htab, hash);

	l = lookup_elem_raw(head, hash, key, key_size);

	if (l) {
		hlist_del_rcu(&l->hash_node);
		htab->count--;
		kfree_rcu(l, rcu);
		ret = 0;
	}

	raw_spin_unlock_irqrestore(&htab->lock, flags);
	return ret;
}

static void delete_all_elements(struct bpf_htab *htab)
{
	int i;

	for (i = 0; i < htab->n_buckets; i++) {
		struct hlist_head *head = select_bucket(htab, i);
		struct hlist_node *n;
		struct htab_elem *l;

		hlist_for_each_entry_safe(l, n, head, hash_node) {
			hlist_del_rcu(&l->hash_node);
			htab->count--;
			kfree(l);
		}
	}
}

/* Called when map->refcnt goes to zero, either from workqueue or from syscall */
static void htab_map_free(struct bpf_map *map)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);

	/* at this point bpf_prog->aux->refcnt == 0 and this map->refcnt == 0,
	 * so the programs (can be more than one that used this map) were
	 * disconnected from events. Wait for outstanding critical sections in
	 * these programs to complete
	 */
	synchronize_rcu();

	/* some of kfree_rcu() callbacks for elements of this map may not have
	 * executed. It's ok. Proceed to free residual elements and map itself
	 */
	delete_all_elements(htab);
	kvfree(htab->buckets);
	kfree(htab);
}

static const struct bpf_map_ops htab_ops = {
	.map_alloc = htab_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_map_lookup_elem,
	.map_update_elem = htab_map_update_elem,
	.map_delete_elem = htab_map_delete_elem,
};

static struct bpf_map_type_list htab_type __read_mostly = {
	.ops = &htab_ops,
	.type = BPF_MAP_TYPE_HASH,
};

static int __init register_htab_map(void)
{
	bpf_register_map_type(&htab_type);
	return 0;
}
late_initcall(register_htab_map);

/* BPF_MAP_TYPE_PERCPU_HASH - time_in_state.o declares two of these, see the
 * comment above percpu_array_map_alloc() in arraymap.c for why the per-CPU
 * types are needed and for the value layout: the value of an element is one
 * block of num_possible_cpus() per-CPU values and map->value_size is that whole
 * block, which is what the syscall layer copies. */
static struct bpf_map *htab_percpu_map_alloc(union bpf_attr *attr)
{
	/* TEMP DEBUG 2026-09-11: per-CPU alloc disabled to bisect a
	 * slab-corruption panic (see comment in the #if 0 block).
	 * Revert after the bisect. */
	(void) attr;
	return ERR_PTR(-EOPNOTSUPP);
}
#if 0 /* TEMP DEBUG: original body kept for revert */

	union bpf_attr scaled = *attr;
	u64 value_size;

	value_size = (u64) attr->value_size * num_possible_cpus();
	if (value_size > U32_MAX)
		return ERR_PTR(-E2BIG);

	scaled.value_size = (u32) value_size;

	/* htab_map_alloc() validates the scaled value_size (key_size, empty
	 * map, and that the resulting element stays kmalloc-able) and allocates
	 * the buckets and elements */
	return htab_map_alloc(&scaled);
#endif /* TEMP DEBUG */

/* Called from eBPF program: the value of the current CPU only */
static void *htab_percpu_map_lookup_elem(struct bpf_map *map, void *key)
{
	void *value = htab_map_lookup_elem(map, key);

	if (!value)
		return NULL;

	return value + raw_smp_processor_id() * bpf_map_prog_value_size(map);
}

/* Called from eBPF program: a program passes one CPU's worth of value
 * (upstream's pcpu_copy_value() with onallcpus == false) and it lands in the
 * current CPU's slice only.  An existing element is updated in place so that
 * the other CPUs' slices keep their data, as upstream does; a new element is
 * created with the other slices zeroed - upstream gets those zeroes from the
 * per-CPU allocator, while an element here comes from kmalloc().  The whole
 * block is written by the syscall path through htab_map_update_elem(). */
static int htab_percpu_map_update_elem(struct bpf_map *map, void *key,
				       void *value, u64 map_flags)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_head *head;
	struct htab_elem *l_new, *l_old;
	unsigned long flags;
	u32 value_size, value_off, hash, key_size;
	int ret;

	if (map_flags > BPF_EXIST)
		/* unknown flags */
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;
	value_size = bpf_map_prog_value_size(map);
	value_off = raw_smp_processor_id() * value_size;

	hash = htab_map_hash(key, key_size);

	/* allocate new element outside of lock */
	l_new = kmalloc(htab->elem_size, GFP_ATOMIC | __GFP_NOWARN);
	if (!l_new)
		return -ENOMEM;

	memcpy(l_new->key, key, key_size);
	memset(l_new->key + round_up(key_size, 8), 0, map->value_size);
	memcpy(l_new->key + round_up(key_size, 8) + value_off, value, value_size);
	l_new->hash = hash;

	/* bpf_map_update_elem() can be called in_irq() */
	raw_spin_lock_irqsave(&htab->lock, flags);

	head = select_bucket(htab, hash);

	l_old = lookup_elem_raw(head, hash, key, key_size);

	if (l_old) {
		if (map_flags == BPF_NOEXIST) {
			/* elem already exists */
			ret = -EEXIST;
			goto free_new;
		}
		/* per-CPU hash map can update the value in place */
		memcpy(l_old->key + round_up(key_size, 8) + value_off,
		       value, value_size);
		ret = 0;
		goto free_new;
	}

	if (map_flags == BPF_EXIST) {
		/* elem doesn't exist, cannot update it */
		ret = -ENOENT;
		goto free_new;
	}

	if (unlikely(htab->count >= map->max_entries)) {
		/* if elem with this 'key' doesn't exist and we've reached
		 * max_entries limit, fail insertion of new elem
		 */
		ret = -E2BIG;
		goto free_new;
	}

	/* add new element to the head of the list, so that concurrent
	 * search will find it before old elem
	 */
	hlist_add_head_rcu(&l_new->hash_node, head);
	htab->count++;
	raw_spin_unlock_irqrestore(&htab->lock, flags);

	return 0;

free_new:
	raw_spin_unlock_irqrestore(&htab->lock, flags);
	kfree(l_new);
	return ret;
}

static const struct bpf_map_ops htab_percpu_map_ops = {
	.map_alloc = htab_percpu_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_percpu_map_lookup_elem,
	.map_lookup_elem_sys_only = htab_map_lookup_elem,
	.map_update_elem = htab_percpu_map_update_elem,
	.map_update_elem_sys_only = htab_map_update_elem,
	.map_delete_elem = htab_map_delete_elem,
};

static struct bpf_map_type_list htab_percpu_type __read_mostly = {
	.ops = &htab_percpu_map_ops,
	.type = BPF_MAP_TYPE_PERCPU_HASH,
};

static int __init register_htab_percpu_map(void)
{
	bpf_register_map_type(&htab_percpu_type);
	return 0;
}
late_initcall(register_htab_percpu_map);

/* BPF_MAP_TYPE_DEVMAP_HASH - tethering offload.o declares one.  The XDP data
 * path and the devmap redirect machinery do not exist on 3.18, so this is a
 * bring-up stub (2026-09-11): a thin alias over the ordinary HASH map.  The
 * file-static htab helpers are reused verbatim for alloc/lookup/update/
 * delete/get_next_key/free; only the reported map_type differs.  Programs
 * using the map verify and load but are never executed on this kernel. */
static struct bpf_map *devmap_hash_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map;

	map = htab_map_alloc(attr);
	if (IS_ERR(map))
		return map;

	map->map_type = BPF_MAP_TYPE_DEVMAP_HASH;
	return map;
}

static const struct bpf_map_ops devmap_hash_ops = {
	.map_alloc = devmap_hash_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_map_lookup_elem,
	.map_update_elem = htab_map_update_elem,
	.map_delete_elem = htab_map_delete_elem,
};

static struct bpf_map_type_list devmap_hash_type __read_mostly = {
	.ops = &devmap_hash_ops,
	.type = BPF_MAP_TYPE_DEVMAP_HASH,
};

static int __init register_devmap_hash_map(void)
{
	bpf_register_map_type(&devmap_hash_type);
	return 0;
}
late_initcall(register_devmap_hash_map);
