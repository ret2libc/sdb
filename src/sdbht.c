#include "sdbht.h"

SDB_API SdbHt* sdb_ht_new() {
	return ht_new ((DupValue)strdup, (HtKvFreeFunc)sdb_kv_free, (CalcSize)strlen);
}

static bool sdb_ht_internal_insert(SdbHt* ht, const char* key,
				    const char* value, bool update) {
	if (!ht || !key || !value) {
		return false;
	}
	SdbKv* kvp = calloc (1, sizeof (SdbKv));
	if (kvp) {
		SDBKV_KEY (kvp) = strdup ((void *)key);
		SDBKV_VALUE (kvp) = strdup ((void *)value);
		SDBKV_KEY_LEN (kvp) = strlen (SDBKV_KEY (kvp));
		SDBKV_VALUE_LEN (kvp) = strlen (SDBKV_VALUE (kvp));
		kvp->expire = 0;
		return ht_insert_kv (ht, (HtKv*)kvp, update);
	}
	return false;
}

SDB_API bool sdb_ht_insert(SdbHt* ht, const char* key, const char* value) {
	return sdb_ht_internal_insert (ht, key, value, false);
}

SDB_API bool sdb_ht_insert_kvp(SdbHt* ht, SdbKv *kvp, bool update) {
	return ht_insert_kv (ht, (HtKv*)kvp, update);
}

SDB_API bool sdb_ht_update(SdbHt *ht, const char *key, const char*value) {
	return sdb_ht_internal_insert (ht, key, value, true);
}

SDB_API SdbKv* sdb_ht_find_kvp(SdbHt* ht, const char* key, bool* found) {
	return (SdbKv *)ht_find_kv (ht, key, found);
}

SDB_API char* sdb_ht_find(SdbHt* ht, const char* key, bool* found) {
	return (char *)ht_find (ht, key, found);
}

SDB_API void sdb_ht_free(SdbHt *ht) {
	ht_free (ht);
}

SDB_API bool sdb_ht_delete(SdbHt* ht, const char *key) {
	return ht_delete (ht, key);
}

SDB_API void sdb_ht_free_deleted(SdbHt* ht) {
	ht_free_deleted (ht);
}
