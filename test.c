#include <sys/ioctl.h>
#include "sysinfo.h"
#include "log.h"

LOG_DEF()

int main(int argc, char *argv[])
{
    set_log_app(argv[0]);
    test_all_sysinfo_api();
    return 0;
}   