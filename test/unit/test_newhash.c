#include "minunit.h"
#include <sdb.h>
#include <new_ht.h>

typedef struct test_t {
	char *v, *k;
} test_t;

test_t *test_t_new(const char *k, const char *v) {
	test_t *res = malloc(sizeof(test_t));
	res->k = strdup(k);
	res->v = strdup(v);
	return res;
}

void test_t_free(test_t *t) {
	free (t->k);
	free (t->v);
	free (t);
}

char *test_t_key(test_t *t) {
	return t->k;
}

SdbNewHash *setup() {
	SdbNewHashProp prop;
	prop.freefn = (NewHtFreeFunction)test_t_free;
	prop.keyfn = (NewHtGetKeyFunction)test_t_key;
	prop.hashfn = (NewHtHashFunction)sdb_hash;
	prop.cmpfn = (NewHtListComparator)strcmp;
	SdbNewHash *ht = new_ht_new (&prop);
	return ht;
}

bool test_ht_insert_lookup(void) {
	SdbNewHash *ht = setup();

	new_ht_insert (ht, test_t_new("AAAA", "vAAAA"));
	new_ht_insert (ht, test_t_new("BBBB", "vBBBB"));
	new_ht_insert (ht, test_t_new("CCCC", "vCCCC"));

	test_t *t;
	t = (test_t *)new_ht_find (ht, "BBBB", NULL);
	mu_assert_streq (t->v, "vBBBB", "BBBB value wrong");
	t = (test_t *)new_ht_find (ht, "AAAA", NULL);
	mu_assert_streq (t->v, "vAAAA", "AAAA value wrong");
	t = (test_t *)new_ht_find (ht, "CCCC", NULL);
	mu_assert_streq (t->v, "vCCCC", "CCCC value wrong");

	new_ht_free (ht);
	mu_end;
}

bool test_ht_update_lookup(void) {
	SdbNewHash *ht = setup();
	test_t *t;

	new_ht_insert (ht, test_t_new ("AAAA", "vAAAA"));
	new_ht_insert (ht, test_t_new ("BBBB", "vBBBB"));

	// test update to add a new element
	new_ht_update (ht, test_t_new ("CCCC", "vCCCC"));
	t = (test_t *)new_ht_find (ht, "CCCC", NULL);
	mu_assert_streq (t->v, "vCCCC", "CCCC value wrong");

	// test update to replace an existing element
	new_ht_update (ht, test_t_new ("AAAA", "vDDDD"));
	t = (test_t *)new_ht_find (ht, "AAAA", NULL);
	mu_assert_streq (t->v, "vDDDD", "DDDD value wrong");

	new_ht_free (ht);
	mu_end;
}

bool test_ht_delete(void) {
	SdbNewHash *ht = setup();
	mu_assert ("nothing should be deleted", !new_ht_delete (ht, "non existing"));

	new_ht_insert (ht, test_t_new ("AAAA", "vAAAA"));
	mu_assert ("AAAA should be deleted", new_ht_delete (ht, "AAAA"));
	mu_assert ("AAAA still there", !new_ht_find (ht, "AAAA", NULL));

	new_ht_free (ht);
	mu_end;
}

int all_tests() {
	mu_run_test (test_ht_insert_lookup);
	mu_run_test (test_ht_update_lookup);
	mu_run_test (test_ht_delete);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
