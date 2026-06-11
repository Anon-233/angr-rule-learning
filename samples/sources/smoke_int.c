#define KEEP __attribute__((noinline, used))

KEEP int add_i32(int a, int b) {
    return a + b;
}

KEEP unsigned xor_shift_u32(unsigned x, unsigned y) {
    unsigned t = x ^ y;
    return (t << 3) | (x >> 5);
}

KEEP long mix_i64(long a, long b, long c) {
    long t = a - b;
    return (t & c) + (a | b);
}

KEEP int cmp_select_i32(int a, int b) {
    return a < b ? a - b : a + b;
}

KEEP unsigned branch_accum_u32(unsigned x) {
    if ((x & 1u) != 0u) {
        return x + 7u;
    }
    return x ^ 0x55u;
}

KEEP int store_load_i32(int *p, int v) {
    *p = v + 1;
    return *p;
}

int main(void) {
    int value = 3;
    int stored = store_load_i32(&value, 9);
    return add_i32(1, 2)
        + cmp_select_i32(value, stored)
        + (int)xor_shift_u32(7u, 11u)
        + (int)branch_accum_u32(5u)
        + (int)mix_i64(13, 4, 6);
}
