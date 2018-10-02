#ifndef __SDB_HT_H
#define __SDB_HT_H

#include "ht.h"

/** keyvalue pair **/
typedef struct sdb_kv {
	//sub of HtKv so we can cast safely
	char *key;
	char *value;
	ut32 key_len;
	ut32 value_len;
	ut32 cas;
	ut64 expire;
} SdbKv;

#define SDBKV_KEY(kv) ((kv)->key)
#define SDBKV_VALUE(kv) ((kv)->value)
#define SDBKV_KEY_LEN(kv) ((kv)->key_len)
#define SDBKV_VALUE_LEN(kv) ((kv)->value_len)

SDB_API SdbKv* sdb_kv_new2(const char *k, int kl, const char *v, int vl);
extern SdbKv* sdb_kv_new(const char *k, const char *v);
extern ut32 sdb_hash(const char *key);
extern void sdb_kv_free(SdbKv *kv);

SDB_API SdbHt* sdb_ht_new(void);
// Destroy a hashtable and all of its entries.
SDB_API void sdb_ht_free(SdbHt* ht);
SDB_API void sdb_ht_free_deleted(SdbHt* ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
SDB_API bool sdb_ht_insert(SdbHt* ht, const char* key, const char* value);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
SDB_API bool sdb_ht_insert_kvp(SdbHt* ht, SdbKv *kvp, bool update);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
SDB_API bool sdb_ht_update(SdbHt* ht, const char* key, const char* value);
// Delete a key from the hashtable.
SDB_API bool sdb_ht_delete(SdbHt* ht, const char* key);
// Find the value corresponding to the matching key.
SDB_API char* sdb_ht_find(SdbHt* ht, const char* key, bool* found);
// Find the KeyValuePair corresponding to the matching key.
SDB_API SdbKv* sdb_ht_find_kvp(SdbHt* ht, const char* key, bool* found);

#endif // __SDB_HT_H
