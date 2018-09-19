/* radare2 - BSD 3 Clause License - crowell, pancake 2016 */

#include "ht.h"
#include "sdb.h"

#define DEFAULT_LOAD_FACTOR 0.92
#define S_ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))

// Sizes of the ht.
const int ht_primes_sizes[] = {
	3, 7, 17, 37, 59, 107, 197, 293, 521, 919, 1597, 2801, 5839, 10103,
	17519, 25229, 52361, 90523, 156437, 270371, 467237, 807403, 1674319,
	2009191, 3471899, 4166287, 7199369,
};

#define HASHFN(ht, k) (ht->hashfn ? ht->hashfn (k) : (ut32)(ut64)(k))
#define DUPKEY(ht, k) (ht->dupkey ? ht->dupkey (k) : (k))
#define DUPVAL(ht, v) (ht->dupvalue ? ht->dupvalue (v) : (v))
#define CALCSIZEK(ht, k) (ht->calcsizeK ? ht->calcsizeK (k) : 0)
#define CALCSIZEV(ht, v) (ht->calcsizeV ? ht->calcsizeV (v) : 0)
#define COMPUTE_SIZE(idx, sz) ((idx) != UT32_MAX ? ht_primes_sizes[(idx)] : (sz))

static inline bool ht_equal(SdbHt *ht, const char *key, ut32 key_len, HtKv *kv) {
	if (key_len != kv->key_len) {
		return false;
	}

	bool res = key == kv->key;
	if (!res && ht->cmp) {
		return !ht->cmp (key, kv->key);
	}
	return res;
}

static ut32 get_prime_idx(ut32 base_idx, float load_factor, ut32 size) {
	while (base_idx < S_ARRAY_SIZE (ht_primes_sizes) && (ut32)(load_factor * ht_primes_sizes[base_idx]) < size) {
		base_idx++;
	}
	if (base_idx == S_ARRAY_SIZE (ht_primes_sizes)) {
		return UT32_MAX;
	}

	return base_idx;
}

// Create a new hashtable and return a pointer to it.
// size - number of buckets in the hashtable
// hashfunction - the function that does the hashing, must not be null.
// comparator - the function to check if values are equal, if NULL, just checks
// == (for storing ints).
// keydup - function to duplicate to key (eg strdup), if NULL just does strup.
// valdup - same as keydup, but for values but if NULL just assign
// pair_free - function for freeing a keyvaluepair - if NULL just does free.
// calcsize - function to calculate the size of a value. if NULL, just stores 0.
static SdbHt* internal_ht_new(ut32 size, ut32 prime_idx, HashFunction hashfunction,
				ListComparator comparator, DupKey keydup,
				DupValue valdup, HtKvFreeFunc pair_free,
				CalcSize calcsizeK, CalcSize calcsizeV) {
	SdbHt* ht = calloc (1, sizeof (*ht));
	if (!ht) {
		return NULL;
	}

	ht->load_factor = DEFAULT_LOAD_FACTOR;
	ht->size = size;
	ht->prime_idx = prime_idx;
	ht->count = 0;
	ht->hashfn = hashfunction;
	ht->cmp = comparator;
	ht->dupkey = keydup? keydup: NULL;
	ht->dupvalue = valdup? valdup: NULL;
	ht->table = calloc (ht->size, sizeof (SdbList*));
	ht->calcsizeK = calcsizeK? calcsizeK: NULL;
	ht->calcsizeV = calcsizeV? calcsizeV: NULL;
	ht->freefn = pair_free;
	// Because we use calloc, each listptr will be NULL until used */
	return ht;
}

SDB_API bool ht_delete_internal(SdbHt* ht, const char* key, ut32* hash) {
	HtKv* kv;
	SdbListIter* iter;
	ut32 computed_hash = hash ? *hash : HASHFN (ht, key);
	ut32 key_len = CALCSIZEK (ht, key);
	ut32 bucket = computed_hash % ht->size;
	SdbList* list = ht->table[bucket];
	ls_foreach (list, iter, kv) {
		if (ht_equal (ht, key, key_len, kv)) {
			ls_delete (list, iter);
			ht->count--;
			return true;
		}
	}
	return false;
}

SDB_API SdbHt* ht_new(DupValue valdup, HtKvFreeFunc pair_free, CalcSize calcsizeV) {
	return internal_ht_new (ht_primes_sizes[0], 0, (HashFunction)sdb_hash,
		(ListComparator)strcmp, (DupKey)strdup,
		valdup, pair_free, (CalcSize)strlen, calcsizeV);
}

SDB_API SdbHt* ht_new_size(ut32 initial_size, DupValue valdup, HtKvFreeFunc pair_free, CalcSize calcsizeV) {
	ut32 idx = get_prime_idx (0, DEFAULT_LOAD_FACTOR, initial_size);
	ut32 sz = COMPUTE_SIZE (idx, initial_size);
	return internal_ht_new (sz, idx, (HashFunction)sdb_hash,
		(ListComparator)strcmp, (DupKey)strdup,
		valdup, pair_free, (CalcSize)strlen, calcsizeV);
}

SDB_API void ht_free(SdbHt* ht) {
	if (!ht) {
		return;
	}

	ut32 i;
	for (i = 0; i < ht->size; i++) {
		ls_free (ht->table[i]);
	}
	free (ht->table);
	free (ht);
}

static void insert_kv_nogrow(SdbHt *ht, HtKv *kv, ut32 *hash) {
	ut32 computed_hash = hash ? *hash : HASHFN (ht, kv->key);
	ut32 bucket = computed_hash % ht->size;
	if (!ht->table[bucket]) {
		ht->table[bucket] = ls_newf ((SdbListFree)ht->freefn);
	}
	ls_prepend (ht->table[bucket], kv);
	ht->count++;
}

// Increases the size of the hashtable by 2.
static void internal_ht_grow(SdbHt* ht) {
	SdbHt* ht2;
	SdbHt swap;
	HtKv* kv;
	SdbListIter *iter, *tmp;
	ut32 i, sz;
	ht->prime_idx = get_prime_idx (ht->prime_idx, ht->load_factor, ht->size);
	sz = COMPUTE_SIZE (ht->prime_idx, ht->size * 2);
	ht2 = internal_ht_new (sz, ht->prime_idx, ht->hashfn, ht->cmp,
		ht->dupkey, ht->dupvalue, (HtKvFreeFunc)ht->freefn,
		ht->calcsizeK, ht->calcsizeV);
	for (i = 0; i < ht->size; i++) {
		if (!ht->table[i]) {
			continue;
		}

		ht->table[i]->free = NULL;
		ls_foreach_safe (ht->table[i], iter, tmp, kv) {
			insert_kv_nogrow (ht2, kv, NULL);
			ls_delete (ht->table[i], iter);
		}
	}
	// And now swap the internals.
	swap = *ht;
	*ht = *ht2;
	*ht2 = swap;
	ht_free (ht2);
	printf("grown ht->size = %d\n", ht->size);
}

static HtKv *find_kv(SdbHt* ht, const char* key, bool* found) {
	if (!ht || !key) {
		return NULL;
	}
	ut32 hash, bucket;
	SdbListIter* iter;
	HtKv* kv;
	ut32 key_len = CALCSIZEK (ht, key);
	hash = HASHFN (ht, key);
	bucket = hash % ht->size;
	ls_foreach (ht->table[bucket], iter, kv) {
		if (ht_equal (ht, key, key_len, kv)) {
			if (found) {
				*found = true;
			}
			return kv;
		}
	}
	if (found) {
		*found = false;
	}
	return NULL;
}

static bool internal_ht_insert_kv(SdbHt *ht, HtKv *kv, bool update) {
	bool found = false;
	if (!ht || !kv) {
		return false;
	}
	ut32 hash = HASHFN (ht, kv->key);
	if (update) {
		(void)ht_delete_internal (ht, kv->key, &hash);
	} else {
		(void)find_kv (ht, kv->key, &found);
	}
	if (update || !found) {
		insert_kv_nogrow (ht, kv, &hash);
		// Check if we need to grow the table.
		if (ht->count >= (ut32)(ht->load_factor * ht->size)) {
			internal_ht_grow (ht);
		}
		return true;
	}
	return false;
}

static bool internal_ht_insert(SdbHt* ht, bool update, char* key, void* value) {
	if (!ht || !key) {
		return false;
	}
	HtKv* kv = calloc (1, sizeof (HtKv));
	if (kv) {
		kv->key = DUPKEY (ht, key);
		kv->value = DUPVAL (ht, value);
		kv->key_len = CALCSIZEK (ht, kv->key);
		kv->value_len = CALCSIZEV (ht, kv->value);

		if (!internal_ht_insert_kv (ht, kv, update)) {
			if (ht->freefn) {
				ht->freefn (kv);
			}
			return false;
		}
		return true;
	}
	return false;
}

SDB_API bool ht_insert_kv(SdbHt *ht, HtKv *kv, bool update) {
	return internal_ht_insert_kv (ht, kv, update);
}
// Inserts the key value pair key, value into the hashtable.
// Doesn't allow for "update" of the value.
SDB_API bool ht_insert(SdbHt* ht, char* key, void* value) {
	return internal_ht_insert (ht, false, key, value);
}

// Inserts the key value pair key, value into the hashtable.
// Does allow for "update" of the value.
SDB_API bool ht_update(SdbHt* ht, char* key, void* value) {
	return internal_ht_insert (ht, true, key, value);
}

// Returns the corresponding SdbKv entry from the key.
// If `found` is not NULL, it will be set to true if the entry was found, false
// otherwise.
SDB_API HtKv* ht_find_kv(SdbHt* ht, const char* key, bool* found) {
	return find_kv (ht, key, found);
}

// Looks up the corresponding value from the key.
// If `found` is not NULL, it will be set to true if the entry was found, false
// otherwise.
SDB_API void* ht_find(SdbHt* ht, const char* key, bool* found) {
	bool _found = false;
	if (!found) {
		found = &_found;
	}
	HtKv* kv = find_kv (ht, key, found);
	return (kv && *found)? kv->value : NULL;
}

// Deletes a entry from the hash table from the key, if the pair exists.
SDB_API bool ht_delete(SdbHt* ht, const char* key) {
	return ht_delete_internal (ht, key, NULL);
}

SDB_API void ht_foreach(SdbHt *ht, HtForeachCallback cb, void *user) {
	if (!ht) {
		return;
	}
	ut32 i = 0;
	HtKv *kv;
	SdbListIter *iter;
	for (i = 0; i < ht->size; i++) {
		ls_foreach (ht->table[i], iter, kv) {
			if (!kv || !kv->key) {
				continue;
			}
			if (!cb (user, kv->key, kv->value)) {
				return;
			}
		}
	}
}
