# svc_hook
svc hook demo

- hook openat read 
```
 svc_hook(__NR_openat, NULL, (void *)&after_openat, NULL);
 svc_hook(__NR_read, NULL, NULL, NULL);
```

- trace open and read
```
redfin:/ # /data/local/tmp/main
===== handle syscall no 56 : sys_openat
after_openat /proc/self/maps
open fd is 3
===== handle syscall no 63 : sys_read
read buf : 65348f7000-65349

===== handle syscall no 63 : sys_read
```
