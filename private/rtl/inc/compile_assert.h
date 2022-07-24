#pragma once

/* Create an assert that will trigger a compile error if it fails. */
#define compile_assert(name, expr) \
        typedef int __assert_failed_##name[(expr) ? 1 : -1] __attribute__((unused));

/*
 * The following code generates a compile-time error if the type size is not
 * the correct one. This is to ensure ABI compatibility when we cross ELF/PE
 * process boundary.
 */
#define assert_size_correct(type, expected_bytes)		\
    typedef unsigned long __type_##type##_size_incorrect[	\
	(sizeof(type) == expected_bytes) ? 1 : -1]
