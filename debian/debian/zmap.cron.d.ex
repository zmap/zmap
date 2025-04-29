#
# Regular cron jobs for the zmap package.
#
0 4	* * *	root	[ -x /usr/bin/zmap_maintenance ] && /usr/bin/zmap_maintenance
