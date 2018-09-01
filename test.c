#include <sys/ioctl.h>
#include "sysinfo.h"
#include "log.h"

LOG_DEF()

int main(int argc, char const *argv[])
{
    char ifname[32] = {0};
    char * gateway = NULL;
    char * gateway_if = NULL;
    char * macstr = NULL;
    char * ipstr = NULL;
    char * info = NULL;

    if(argc < 2){
        printf("Usage:%s ifname\n",argv[0]);
        exit(-1);
    }
    set_log_app((char *)argv[0]);
    strcpy(ifname,argv[1]);

    test_get_sysinfo(ifname);

    log_string(ifname);
    log_string(get_gateway());
    log_string(get_gateway_if());

    puts("\n");
    log_string(get_if_macstr(ifname));
    log_string(macstr_fmt(get_if_macstr(ifname),"-"));
    log_string(macstr_unfmt(macstr_fmt(get_if_macstr(ifname),"-"),"-"));
    // log_string(macstr_unfmt(macstr_fmt(get_if_macstr(ifname),"-"),""));
    // log_string(macstr_unfmt(macstr_fmt(get_if_macstr(ifname),"-"),":"));
    puts("\n");
    log_string(get_if_macstr(ifname));
    log_string(macstr_fmt(get_if_macstr(ifname),""));
    log_string(macstr_unfmt(macstr_fmt(get_if_macstr(ifname),""),""));
    // log_string(macstr_unfmt(macstr_fmt(get_if_macstr(ifname),""),"-"));
    // log_string(macstr_unfmt(macstr_fmt(get_if_macstr(ifname),""),":"));
    puts("\n");
    log_string(get_if_ipstr("enp0s8"));
    log_string(get_if_ipstr("enp0s10"));
    log_string(get_if_ipstr("enp0s15"));
    log_string(get_if_ipstr("wlan0"));
    log_string(get_if_ipstr("wlan1"));
    puts("\n");
    log_string(get_if_info(ifname,SIOCGIFHWADDR));
    log_string(macstr_fmt(get_if_info(ifname,SIOCGIFHWADDR),"-"));
    log_string(get_if_info(ifname,SIOCGIFADDR));
    log_string(get_if_info(ifname,SIOCGIFNETMASK));
    log_string(get_if_info("enp0s11",SIOCGIFNETMASK));

    /* code */
    return 0;
}   