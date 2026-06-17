#define KEEP __attribute__((noinline, used))

/* ── integer arithmetic ── */
KEEP int add(int a, int b)          { return a + b; }
KEEP int sub(int a, int b)          { return a - b; }
KEEP int mul(int a, int b)          { return a * b; }
KEEP int div_op(int a, int b)       { return b ? a / b : 0; }
KEEP unsigned udiv(unsigned a, unsigned b) { return b ? a / b : 0u; }

/* ── bitwise ── */
KEEP int bit_and(int a, int b)      { return a & b; }
KEEP int bit_or (int a, int b)      { return a | b; }
KEEP int bit_xor(int a, int b)      { return a ^ b; }
KEEP int bit_shl(int a, int n)      { return a << n; }
KEEP int bit_shr(int a, int n)      { return a >> n; }
KEEP unsigned bit_shr_u(unsigned a, int n) { return a >> n; }

/* ── logic / conditional ── */
KEEP int cmplt(int a, int b)        { return a < b; }
KEEP int cmpeq(int a, int b)        { return a == b; }
KEEP int select_op(int c, int a, int b) { return c ? a : b; }

/* ── memory load / store ── */
KEEP int load(const int *p)         { return *p; }
KEEP void store(int *p, int v)      { *p = v; }
KEEP int load_add(int *p, int v)    { int t = *p; *p = t + v; return *p; }
KEEP int load_store(int *p, int v)  { int old = *p; *p = v; return old; }

/* ── frame / stack ── */
KEEP int frame_read(int a, int b, int c) {
    int arr[4] = {a, b, c, 0};
    return arr[0] + arr[1] + arr[2];
}
KEEP void frame_write(int *out) {
    int local[2] = {11, 22};
    out[0] = local[0];
    out[1] = local[1];
}
KEEP int frame_mixed(int a, int b) {
    int x = a + b;
    int y = a - b;
    return x * y;
}

/* ── indexed memory ── */
KEEP int idx_read(const int *p, int i)      { return p[i]; }
KEEP void idx_write(int *p, int i, int v) { p[i] = v; }
KEEP int idx_rmw(int *p, int i, int v)   { int old = p[i]; p[i] = v; return old; }

int main(void) {
    int buf[4] = {10, 20, 30, 40};
    int x = add(3, 5);
    int y = mul(x, 2);
    int z = load_add(buf, y);
    frame_read(x, y, z);
    frame_write(buf);
    frame_mixed(x, y);
    idx_write(buf, 2, 7);
    return sub(bit_and(x, y), bit_or(z, buf[0]))
         + cmplt(x, y) + cmpeq(z, buf[1])
         + select_op(cmplt(x, y), x, y)
         + idx_read(buf, 1) + idx_rmw(buf, 3, 99);
}
