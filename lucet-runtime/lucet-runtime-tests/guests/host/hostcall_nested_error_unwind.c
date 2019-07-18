#include <stddef.h>

extern void hostcall_test_func_hostcall_nested_error_unwind1(void (*)(void));
extern void hostcall_test_func_hostcall_nested_error_unwind2(void);

void guest_func(void) {
    hostcall_test_func_hostcall_nested_error_unwind2();
}

int main(void)
{
    hostcall_test_func_hostcall_nested_error_unwind1(guest_func);
    return 0;
}
