#!/bin/sh
# Remove ShellGate from OpenWrt. Add --purge to also delete /etc/shellgate.
/etc/init.d/shellgate stop 2>/dev/null
/etc/init.d/shellgate disable 2>/dev/null
rm -f /etc/init.d/shellgate /usr/bin/shellgate
sed -i '\|^/usr/bin/shellgate$|d; \|^/etc/init.d/shellgate$|d; \|^/etc/shellgate/$|d' /etc/sysupgrade.conf
[ "$1" = "--purge" ] && rm -rf /etc/shellgate /var/log/shellgate
echo "ShellGate removed."
