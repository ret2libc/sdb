/* radare2 - BSD 3 Clause License - 2016 - crowell */

#ifndef __NEW_HT_H
#define __NEW_HT_H

#include "ls.h"
#include "types.h"

typedef void (*NewHtFreeFunction)(void*);
typedef void* (*NewHtGetKeyFunction)(const void*);
typedef ut32 (*NewHtHashFunction)(const void*);
typedef int (*NewHtListComparator)(const void *a, const void *b);

typedef struct new_ht_prop_t {
	NewHtGetKeyFunction keyfn; // Function for getting the key from an object.
	NewHtListComparator cmpfn; // Function for comparing values. Returns 0 if eq.
	NewHtHashFunction hashfn; // Function for hashing items in the hash table.
	NewHtFreeFunction freefn; // Function to free the keyvalue store, if NULL, just calls regular free.
} SdbNewHashProp;

/** ht **/
typedef struct new_ht_t {
	ut32 size; // size of the hash table in buckets.
	ut32 count; // number of stored elements.
	SdbNewHashProp prop; // properties of the hash table.
	SdbList/*<void*>*/** table;  // Actual table.
	ut32 load_factor; // load factor before doubling in size.
	ut32 prime_idx;
} SdbNewHash;

// Create a new hash table.
SdbNewHash* new_ht_new(SdbNewHashProp *prop);

// Get the current properties of the hash table.
SdbNewHashProp new_ht_get_prop(SdbNewHash *ht);

// Change the properties of the hash table.
void new_ht_set_prop(SdbNewHash* ht, SdbNewHashProp* prop);

// Destroy a hashtable and all of its entries.
void new_ht_free(SdbNewHash* ht);

// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
bool new_ht_insert(SdbNewHash* ht, const void *obj);

// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
bool new_ht_update(SdbNewHash* ht, const void *obj);

// Delete a key from the hashtable.
bool new_ht_delete(SdbNewHash* ht, const char* key);

// Find the value corresponding to the matching key.
void* new_ht_find(SdbNewHash* ht, const char* key, bool* found);

#endif // __NEW_HT_H
