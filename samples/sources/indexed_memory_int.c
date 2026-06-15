#define KEEP __attribute__((noinline, used))

KEEP int read_indexed(const int *p, int i) {
    return p[i];
}

KEEP void write_indexed(int *p, int i, int v) {
    p[i] = v;
}

KEEP int copy_indexed(int *dst, const int *src, int i) {
    dst[i] = src[i];
    return dst[i];
}

int main(void) {
    int values[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    int out[8] = {0};
    int a = read_indexed(values, 3);
    write_indexed(out, 2, a);
    int b = copy_indexed(out, values, 4);
    return a + b + out[2];
}
