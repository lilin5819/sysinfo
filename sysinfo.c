#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>

#define FREE(p) do{ \
    if(p) \
        free(p);\
    p = NULL;\
}while(0)

#define FCLOSE(stream) do{ \
    if(stream)\
        fclose(stream);\
    stream = NULL;\
}while(0)

long get_uptime()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.uptime;        
}
//KB
unsigned long get_totalram()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.totalram>>10;    
}
//KB
unsigned long get_freeram()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.freeram>>10;    
}

double get_freeram_rate()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return 100.0*info.freeram/info.totalram;    
}

unsigned int get_procs()
{
    struct sysinfo info;
    if(-1 == sysinfo(&info))
        return 0;

    return info.procs;  
}

void strip_r(char *str)
{
    char *p = str + strlen(str) - 1;
    while(*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t')
    {
        *p = '\0';
        p--;
    }
}

char* get_file_value(char *filename)
{
    FILE *stream = NULL;
    char *line = NULL;
    ssize_t nread = 0,len = 0;

    if (!(stream = fopen(filename, "r")) ) {
        perror("fopen");
        goto OUT;
    }

    nread = getline(&line, &len, stream);
    strip_r(line);

OUT:
    FCLOSE(stream);
    // if(!nread)
    //     return strdup("");
    return line;
}

char* get_sysdev_info(char *ifname,char *item)
{
    char filename[64];

    sprintf(filename,"/sys/class/net/%s/%s",ifname,item);
    return get_file_value(filename);
}


typedef struct cpuinfo_item{
    char key[32];
    char value[1024];
}cpuinfo_item;

int cpuinfo_query(char *find_key,cpuinfo_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    max = max >= 8 ? 8 : max;
    if(!(*item = (cpuinfo_item *)malloc(max * sizeof(cpuinfo_item))) ) {
        perror("malloc");
        goto OUT;
    }

    if (!(stream = fopen("/proc/cpuinfo", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nread <= 1 ) continue;
        sscanf(line,"%[^:]: %[^\n]",(*item)[nfound].key,(*item)[nfound].value);
        strip_r((*item)[nfound].key);
        if(0 == strcmp((*item)[nfound].key,find_key)){
            // printf("idex=%d key=\"%s\" value=\"%s\"\n",nfound,(*item)[nfound].key,(*item)[nfound].value);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}

typedef struct meminfo_item{
    char key[32];
    char value[32];
    char extra[8];
}meminfo_item;

int meminfo_query(char *find_key,meminfo_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    max = max >= 8 ? 8 : max;
    if(!((*item) = (meminfo_item *)malloc(max * sizeof(meminfo_item)))) {
        perror("malloc");
        goto OUT;
    }

    if (!(stream = fopen("/proc/meminfo", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nline++ == 0 || nread <= 1) continue;
        sscanf(line,"%[^:]: %s %s",(*item)[nfound].key,(*item)[nfound].value,(*item)[nfound].extra);
        if(0 == strcmp((*item)[nfound].key,find_key)){
            // printf("idex=%d key=\"%s\" value=\"%s\" extra=\"%s\"\n",nfound,(*item)[nfound].key,(*item)[nfound].value,(*item)[nfound].extra);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}

typedef struct route_item{
    char ifname[32];
    char dest[32];
    char gateway[32];
    char flags[8];
    char metric[8];
    char mask[32];
}route_item;

enum RT_QUERY_TYPE{
    RT_IFNAME = 0,
    RT_DEST,
    RT_GATEWAY,
    RT_FLAGS,
    RT_METRIC,
    RT_MASK,
};

int route_query(enum RT_QUERY_TYPE type,char *find_key,route_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL,*pkey = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    max = max >= 8 ? 8 : max;
    if(!((*item) = (route_item *)malloc(max * sizeof(route_item)))) {
        perror("malloc");
        goto OUT;
    }

    switch (type){
        case  RT_IFNAME:
            pkey = (*item)->ifname;
            break;
        case  RT_DEST:
            pkey = (*item)->dest;
            break;
        case  RT_GATEWAY:
            pkey = (*item)->gateway;
            break;
        case  RT_FLAGS:
            pkey = (*item)->flags;
            break;
        case  RT_METRIC:
            pkey = (*item)->metric;
            break;
        case  RT_MASK:
            pkey = (*item)->mask;
            break;
        default:
            pkey = (*item)->ifname;
            break;
    }
    if (!(stream = fopen("/proc/net/route", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nline++ == 0 || nread <= 1) continue;
        sscanf(line,"%s %s %s %s %*s %*s %s %s %*s %*s %*s",
            (*item)[nfound].ifname,(*item)[nfound].dest,(*item)[nfound].gateway,(*item)[nfound].flags,(*item)[nfound].metric,(*item)[nfound].mask);
        if(0 == strcmp(pkey,find_key)){
            // printf("ifname=\"%s\" dest=\"%s\" gateway=\"%s\" flags=\"%s\" metric=\"%s\" mask=\"%s\"\n",
                // (*item)[nfound].ifname,(*item)[nfound].dest,(*item)[nfound].gateway,(*item)[nfound].flags,(*item)[nfound].metric,(*item)[nfound].mask);
            pkey  = pkey + sizeof(route_item);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}

typedef struct arp_item{
    char ip[32];
    char type[8];
    char flags[8];
    char mac[32];
    char ifname[32];
}arp_item;

enum ARP_QUERY_TYPE{
    ARP_IP = 0,
    ARP_TYPE,
    ARP_FLAGS,
    ARP_MAC,
    ARP_IFNAME,
};

int arp_query(enum ARP_QUERY_TYPE type,char *find_key,arp_item **item,size_t max)
{
    FILE *stream = NULL;
    char *line = NULL,*pkey = NULL;
    size_t len = 0,nline = 0,nfound = 0;
    ssize_t nread;

    max = max >= 8 ? 8 : max;
    if(!((*item) = (arp_item *)malloc(max * sizeof(arp_item)))) {
        perror("malloc");
        goto OUT;
    }

    switch (type){
        case  ARP_IP:
            pkey = (*item)->ip;
            break;
        case  ARP_TYPE:
            pkey = (*item)->type;
            break;
        case  ARP_FLAGS:
            pkey = (*item)->flags;
            break;
        case  ARP_MAC:
            pkey = (*item)->mac;
            break;
        default:
            pkey = (*item)->ifname;
            break;
    }
    if (!(stream = fopen("/proc/net/arp", "r")) ) {
        perror("fopen");
        goto OUT;
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        if(nline++ == 0 || nread <= 1) continue;
        sscanf(line,"%s %s %s %s %*s %s",
            (*item)[nfound].ip,(*item)[nfound].type,(*item)[nfound].flags,(*item)[nfound].mac,(*item)[nfound].ifname);
        if(0 == strcmp(pkey,find_key)){
            // printf("ip=\"%s\" type=\"%s\" flags=\"%s\" mac=\"%s\" ifname=\"%s\"\n",
                // (*item)[nfound].ip,(*item)[nfound].type,(*item)[nfound].flags,(*item)[nfound].mac,(*item)[nfound].ifname);
            pkey  = pkey + sizeof(arp_item);
            if(++nfound == max) break;
        }
    }

OUT:
    FREE(line);
    FCLOSE(stream);
    return nfound;
}


// /proc/cpuinfo
// /proc/meminfo
// /proc/net/route
// /proc/net/arp
// /proc/net/dev

int main(void)
{
    int ninfo = 0,i = 0;
    cpuinfo_item *cpu_item = NULL;
    meminfo_item *mem_item = NULL;
    route_item *route_item = NULL;
    arp_item *arp_item = NULL;
    char *value = NULL;
    printf("uptime          : %ld\n",get_uptime());//打印从设备开启到现在的时间，单位为秒    
    printf("totalram           : %lu KB\n",get_totalram());//总可用内存大小  
    printf("freeram            : %lu KB\n",get_freeram()); //剩余内存   
    printf("freeram_rate       : %f%%\n",get_freeram_rate());    //进程数
    printf("procs              : %u\n",get_procs());    //进程数

    char *ifname = "enp0s3";
    value = get_sysdev_info(ifname,"speed");
    if(value)
        printf("ifname=\"%s\" mtu=%s\n",ifname,value);

    ninfo = cpuinfo_query("model name",&cpu_item,4);
    for(i=0;i<ninfo;i++)
        printf("key=\"%s\" value=\"%s\"\n",cpu_item[i].key,cpu_item[i].value);



    ninfo = meminfo_query("SwapTotal",&mem_item,4);
    for(i=0;i<ninfo;i++)
        printf("key=\"%s\" value=\"%s\" extra=\"%s\"\n",mem_item[i].key,mem_item[i].value,mem_item[i].extra);
    
    // ninfo = route_query(RT_IFNAME,"enp0s3",&route_item,4);
    ninfo = route_query(RT_DEST,"00000000",&route_item,4);
    for(i=0;i<ninfo;i++)
        printf("ifname=\"%s\" dest=\"%s\" gateway=\"%s\" flags=\"%s\" metric=\"%s\" mask=\"%s\"\n",
            route_item[i].ifname,route_item[i].dest,route_item[i].gateway,route_item[i].flags,route_item[i].metric,route_item[i].mask);

    ninfo = arp_query(ARP_IFNAME,"enp0s3",&arp_item,4);
    for(i=0;i<ninfo;i++)
        printf("ip=\"%s\" type=\"%s\" flags=\"%s\" mac=\"%s\" ifname=\"%s\"\n",
            arp_item[i].ip,arp_item[i].type,arp_item[i].flags,arp_item[i].mac,arp_item[i].ifname);



    FREE(value);
    FREE(cpu_item);
    FREE(mem_item);
    FREE(route_item);
    FREE(arp_item);
    return i;
}