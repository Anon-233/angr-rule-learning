#define KEEP __attribute__((noinline, used))

KEEP int read_int(const int *p) {
    return *p;
}

KEEP void write_int(int *p, int v) {
    *p = v;
}

KEEP int copy_int(int *dst, const int *src) {
    *dst = *src;
    return *dst;
}

int main(void) {
    int x = 42;
    int y = read_int(&x);
    write_int(&x, 99);
    int z = 77;
    int w = copy_int(&z, &x);
    return y + w;
}
