#include <sys/ioctl.h>
#include "sysinfo.h"
#include "log.h"

#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 

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

    log_string(get_gateway());
    log_string(get_gateway_if());

    puts("\n");
    log_string(get_if_macstr("enp0s3"));
    log_string(macstr_fmt(get_if_macstr("enp0s3"),"-"));
    log_string(macstr_unfmt(macstr_fmt(get_if_macstr("enp0s3"),"-"),"-"));
    puts("\n");
    log_string(get_if_macstr("enp0s3"));
    log_string(macstr_fmt(get_if_macstr("enp0s3"),""));
    log_string(macstr_unfmt(macstr_fmt(get_if_macstr("enp0s3"),""),""));
    puts("\n");
    log_string(get_if_ipstr("enp0s8"));
    log_string(get_if_ipstr("enp0s10"));
    log_string(get_if_ipstr("enp0s15"));
    puts("\n");
    log_string(get_if_info("enp0s3",SIOCGIFHWADDR));
    log_string(macstr_fmt(get_if_info("enp0s3",SIOCGIFHWADDR),"-"));
    log_string(get_if_info("enp0s3",SIOCGIFADDR));
    log_string(get_if_info("enp0s3",SIOCGIFNETMASK));
    log_string(get_if_info("enp0s11",SIOCGIFNETMASK));

    /* code */
    return 0;
}   