#include <sys/ioctl.h>
#include "sysinfo.h"
#include "log.h"

LOG_DEF()

int main(int argc, char const *argv[])
{
    char * gateway = NULL;
    char * gateway_if = NULL;
    char * macstr = NULL;
    char * ipstr = NULL;
    char * info = NULL;

    set_log_app((char *)argv[0]);

    test_get_sysinfo();

    gateway = get_gateway();
    log_string(gateway);
    gateway_if = get_gateway_if();
    log_string(gateway_if);

    macstr = get_if_macstr("enp0s3");
    log_string(macstr);
    ipstr = get_if_ipstr("enp0s8");
    log_string(ipstr);
    FREE(ipstr);
    ipstr = get_if_ipstr("enp0s10");
    log_string(ipstr);
    FREE(ipstr);
    ipstr = get_if_ipstr("enp0s15");
    log_string(ipstr);
    FREE(ipstr);

    info = get_if_info("enp0s3",SIOCGIFHWADDR);
    log_string(info);
    FREE(info);
    info = get_if_info("enp0s3",SIOCGIFADDR);
    log_string(info);
    FREE(info);
    info = get_if_info("enp0s3",SIOCGIFNETMASK);
    log_string(info);
    FREE(info);
    info = get_if_info("enp0s11",SIOCGIFNETMASK);
    log_string(info);
    FREE(info);

    FREE(gateway); FREE(gateway_if);FREE(macstr); FREE(ipstr); FREE(ipstr); FREE(ipstr); FREE(info);
    
    /* code */
    return 0;
}   