/* radare2 - BSD 3 Clause License - crowell 2016 */

#include "ht.h"
#include "new_ht.h"
#include "sdb.h"

#define DISABLED_GROW 0

// Sizes of the ht.
const int new_ht_primes_sizes[] = {
#if DISABLED_GROW
	1024,
#else
	3, 7, 11, 17, 23, 29, 37, 47, 59, 71, 89, 107, 131,
	163, 197, 239, 293, 353, 431, 521, 631, 761, 919,
	1103, 1327, 1597, 1931, 2333, 2801, 3371, 4049, 4861,
	5839, 7013, 8419, 10103, 12143, 14591, 17519, 21023,
	25229, 30293, 36353, 43627, 52361, 62851, 75431, 90523,
	108631, 130363, 156437, 187751, 225307, 270371, 324449,
	389357, 467237, 560689, 672827, 807403, 968897, 1162687,
	1395263, 1674319, 2009191, 2411033, 2893249, 3471899,
	4166287, 4999559, 5999471, 7199369
#endif
};

SdbNewHashProp new_ht_get_prop(SdbNewHash *ht) {
	return ht->prop;
}

void new_ht_set_prop(SdbNewHash *ht, SdbNewHashProp *prop) {
	ht->prop.hashfn = prop->hashfn;
	ht->prop.cmpfn = prop->cmpfn;
	ht->prop.keyfn = prop->keyfn;
	// update free function of all lists
	if (ht->prop.freefn != prop->freefn) {
		ut32 i;

		ht->prop.freefn = prop->freefn;
		for (i = 0; i < ht->size; ++i) {
			if (!ht->table[i]) {
				continue;
			}
			ht->table[i]->free = (SdbListFree)ht->prop.freefn;
		}
	}
}

// Create a new hashtable and return a pointer to it.
// size - number of buckets in the hashtable
// prop - properties of the hashtable
static SdbNewHash* internal_new_ht_new(ut32 size, SdbNewHashProp *prop) {
	SdbNewHash* ht = calloc (1, sizeof (SdbNewHash));
	if (!ht) {
		return NULL;
	}
	ht->size = size;
	ht->count = 0;
	ht->prime_idx = 0;
	ht->load_factor = 1;
	ht->table = calloc (ht->size, sizeof (SdbList*));
	new_ht_set_prop (ht, prop);
	// Because we use calloc, each listptr will be NULL until used */
	return ht;
}

bool new_ht_delete_internal(SdbNewHash* ht, const char* key, ut32* hash) {
	ut32 bucket;
	SdbListIter* iter = NULL;
	SdbList* list = NULL;
	const void* kvp = NULL;
	ut32 computed_hash;
	if (!hash) {
		computed_hash = ht->prop.hashfn (key);
	} else {
		computed_hash = *hash;
	}
	bucket = computed_hash % ht->size;
	list = ht->table[bucket];
	ls_foreach (list, iter, kvp) {
		if (ht->prop.cmpfn) {
			if (ht->prop.cmpfn (key, ht->prop.keyfn (kvp)) == 0) {
				ls_delete (list, iter);
				ht->count--;
				return true;
			}
		} else {
			if (key == ht->prop.keyfn (kvp)) {
				ls_delete (list, iter);
				ht->count--;
				return true;
			}
		}
	}
	return false;
}

SdbNewHash* new_ht_new(SdbNewHashProp *prop) {
	SdbNewHashProp dflt_prop;
	if (!prop) {
		prop = &dflt_prop;
		prop->keyfn = NULL;
		prop->freefn = NULL;
		prop->cmpfn = (NewHtListComparator)strcmp;
		prop->hashfn = (NewHtHashFunction)sdb_hash;
	}

	return internal_new_ht_new (new_ht_primes_sizes[0], prop);
}

void new_ht_free(SdbNewHash* ht) {
	ut32 i;
	for (i = 0; i < ht->size; i++) {
		ls_free (ht->table[i]);
	}
	free (ht->table);
	free (ht);
}

// Increases the size of the hashtable by 2.

static void internal_new_ht_grow(SdbNewHash* ht) {
	SdbNewHashProp prop;
	SdbNewHash* ht2;
	SdbNewHash swap;
	const void* kvp;
	SdbListIter* iter;
	ut32 i;
	ut32 sz = new_ht_primes_sizes[ht->prime_idx];
	ht2 = internal_new_ht_new (sz, &(ht->prop));
	ht2->prime_idx = ht->prime_idx;
	for (i = 0; i < ht->size; i++) {
		ls_foreach (ht->table[i], iter, kvp) {
			new_ht_insert (ht2, kvp);
		}
	}
	// And now swap the internals.
	swap = *ht;
	*ht = *ht2;
	*ht2 = swap;

	// Change properties of old ht to avoid freeing used objects
	prop = new_ht_get_prop (ht2);
	prop.freefn = NULL;
	new_ht_set_prop (ht2, &prop);
	new_ht_free (ht2);
}

// Inserts the key value pair key, value into the hashtable.
// if update is true, allow for updates, otherwise return false if the key
// already exists.
static bool internal_new_ht_insert(SdbNewHash* ht, bool update, const void *obj) {
	const char *key = ht->prop.keyfn (obj);
	ut32 hash = ht->prop.hashfn (key);
	ut32 bucket;
	bool found = true;
	if (update) {
		(void)new_ht_delete_internal (ht, key, &hash);
	} else {
		(void)new_ht_find (ht, key, &found);
	}
	if (update || !found) {
		bucket = hash % ht->size;
		if (!ht->table[bucket]) {
			ht->table[bucket] = ls_newf ((SdbListFree)ht->prop.freefn);
		}
		ls_prepend (ht->table[bucket], (void *)obj);
		ht->count++;
		// Check if we need to grow the table.
		if (ht->count >= ht->load_factor * new_ht_primes_sizes[ht->prime_idx]) {
			if (ht->prime_idx < sizeof (new_ht_primes_sizes) / sizeof (new_ht_primes_sizes[0])) {
				ht->prime_idx++;
				internal_new_ht_grow (ht);
			}
		}
		return true;
	}
	return false;
}

// Inserts the key value pair key, value into the hashtable.
// Doesn't allow for "update" of the value.
bool new_ht_insert(SdbNewHash* ht, const void* obj) {
	return internal_new_ht_insert (ht, false, obj);
}

// Inserts the key value pair key, value into the hashtable.
// Does allow for "update" of the value.
bool new_ht_update(SdbNewHash* ht, const void *obj) {
	return internal_new_ht_insert (ht, true, obj);
}

static void* new_ht_find_data(SdbNewHash* ht, const char* key, bool* found) {
	ut32 hash;
	ut32 bucket;
	SdbListIter* iter;
	void* kvp;
	hash = ht->prop.hashfn (key);
	bucket = hash % ht->size;
	ls_foreach (ht->table[bucket], iter, kvp) {
		const char* kvp_key = ht->prop.keyfn (kvp);
		bool match = ht->prop.cmpfn
			? ht->prop.cmpfn (key, kvp_key) == 0
			: key == kvp_key;
		if (match) {
			if (found) {
				*found = true;
			}
			return kvp;
		}
	}
	if (found) {
		*found = false;
	}
	return NULL;
}

// Looks up the corresponding value from the key.
// If `found` is not NULL, it will be set to true if the entry was found, false
// otherwise.
void* new_ht_find(SdbNewHash* ht, const char* key, bool* found) {
	bool _found = false;
	if (!found) {
		found = &_found;
	}
	void* obj = new_ht_find_data (ht, key, found);
	return (obj && *found)? obj : NULL;
}

// Deletes a kvp from the hash table from the key, if the pair exists.
bool new_ht_delete(SdbNewHash* ht, const char* key) {
	return new_ht_delete_internal (ht, key, NULL);
}
