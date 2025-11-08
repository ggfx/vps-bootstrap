#!/usr/bin/env bash
# Debian VPS Bootstrap
# 2024-12-15
# Cornelius Rittner
# Get Variables
export HOSTNAME=$(hostname -f)
export PUBLIC_IPV4=$(hostname -I | awk '{print $1}')

# nice icons
OK="\u2714"   # check
WARN="\u26A0" # warning
ERR="\u2716"  # error

#project=${HOSTNAME%-*}
echo "------------------------------------------------------------"
echo Hostname: $HOSTNAME, IP Address: $PUBLIC_IPV4
echo "------------------------------------------------------------"

# first Update and Upgrade all packages
apt-get update && apt-get -y upgrade
apt-get -y install apt-transport-https ssl-cert net-tools apache2-utils curl sudo logrotate

# Other Basics
apt-get -y install vim htop zip unzip ca-certificates mailutils gnupg locate rsync unattended-upgrades wget bind9-dnsutils python3-systemd

# set tzdata to Europa/Berlin
ln -fs /usr/share/zoneinfo/Europe/Berlin /etc/localtime
DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata
dpkg-reconfigure --frontend noninteractive tzdata
# set locale to de_DE.UTF-8
DEBIAN_FRONTEND=noninteractive apt-get install -y locales
sed -i -e 's/# de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen && echo 'LANG="de_DE.UTF-8"'>/etc/default/locale
dpkg-reconfigure --frontend noninteractive locales && update-locale LANG=de_DE.UTF-8

# Install certbot
if [ ! -x "$(command -v snap)" ]; then
  apt-get -y install snapd
  snap install core; snap refresh core
fi
if [ ! -x "$(command -v certbot)" ]; then
  snap install --classic certbot
  ln -fs /snap/bin/certbot /usr/bin/certbot
fi

# Install postfix as standard smtpd
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix

# set vim colors and dircolors
if [ ! -f ~/.vimrc ]; then
  echo 'syntax on
  colorscheme desert' > ~/.vimrc
elif [ $(grep -L "syntax on" ~/.vimrc) ]; then
  echo 'syntax on
  colorscheme desert' >> ~/.vimrc
fi

# set directory colorization
dircolors -p > ~/.dircolors
sed -i 's/^DIR [0-9;]\+ # directory$/DIR 00;34;47 # directory/' ~/.dircolors
eval "$(dircolors -b ~/.dircolors)"

# create confirmation scripts, added in .bash_aliases
echo 'echo ""
echo ""
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!!! Attention PROD system !!!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo ""
echo ""
echo -n "Run the command \"$@\" now? "
echo -n "(y/n) "
read reply

if [ "$reply" = y ]
then
   /sbin/$@
else
   echo "\"$@\" canceled"
fi' > ~/confirm_script
chmod +x ~/confirm_script

# set .bash_aliases
if [ ! -f ~/.bash_aliases ]; then
  echo "# ~/.bash_aliases: sourced by bashrc.
# colorize the prompt
PS1='\${debian_chroot:+(\$debian_chroot)}\[\[\033[1;33m\]\t:\[\033[1;31m\]\u\[\033[1;36m\]@\h\[\e[0m\]:\w]\\\$ '

# colorize directory listing
test -r ~/.dircolors && eval \"\$(dircolors -b ~/.dircolors)\" || eval \"\$(dircolors -b)\"
export LS_OPTIONS='--color=auto'
alias ls='ls \$LS_OPTIONS'

# listing abbreviations
alias ll='ls -l'
alias la='ll -a'
alias lh='ll -h'
alias lah='la -h'
alias l='lh -A'
alias elsa='ls -lSah'

# traversing abbreviations
alias ..='cd ..'
alias ...='.. && ..'

# alias to confim commands
alias shutdown='~/confirm_script shutdown'
alias reboot='~/confirm_script reboot'" > ~/.bash_aliases
elif [ $(grep -L "alias to confirm" ~/.bash_aliases) ]; then
  echo "# ~/.bash_aliases: sourced by bashrc.
# colorize the prompt
PS1='\${debian_chroot:+(\$debian_chroot)}\[\[\033[1;33m\]\t:\[\033[1;31m\]\u\[\033[1;36m\]@\h\[\e[0m\]:\w]\\\$ '

# colorize directory listing
test -r ~/.dircolors && eval \"\$(dircolors -b ~/.dircolors)\" || eval \"\$(dircolors -b)\"
export LS_OPTIONS='--color=auto'
alias ls='ls \$LS_OPTIONS'

# listing abbreviations
alias ll='ls -l'
alias la='ll -a'
alias lh='ll -h'
alias lah='la -h'
alias l='lh -A'
alias elsa='ls -lSah'

# traversing abbreviations
alias ..='cd ..'
alias ...='.. && ..'

# alias to confim commands
alias shutdown='~/confirm_script shutdown'
alias reboot='~/confirm_script reboot'" >> ~/.bash_aliases
fi

if [ $(grep -L "if \[ -f ~\/\.bash_aliases \];" ~/.bashrc) ]
then
  echo -e "\n# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.
if [ -f ~/.bash_aliases ]; then
  . ~/.bash_aliases
fi" >> ~/.bashrc
fi

source ~/.bash_aliases
source ~/.bashrc

# Install dynamic motd messages for login
apt-get -y install toilet figlet

# clear default motd
echo "" > /etc/motd

cat <<EOF >/etc/update-motd.d/00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2023 Cornelius Rittner
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Cornelius Rittner <rittner@wirth-horn.de>
#             Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release

if [ -z "\$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
        # Fall back to using the very slow lsb_release utility
        DISTRIB_DESCRIPTION=\$(lsb_release -s -d)
fi

toilet -F gay -f small \$(hostname -s)
printf "\n"

printf "Welcome to %s (%s %s %s)\n" "\$DISTRIB_DESCRIPTION" "\$(uname -o)" "\$(uname -r)" "\$(uname -m)"
printf "\n"

toilet -F border -f term FQDN: \$(hostname -f)
printf "\n"
EOF
chmod +x /etc/update-motd.d/00-header

cat <<EOF >/etc/update-motd.d/01-sysinfo
#!/bin/bash
#
#    01-sysinfo - generate the system information
#    Copyright (C) 2023 Cornelius Rittner
#
#    Authors: Cornelius Rittner <rittner@wirth-horn.de>
#

sysinfo(){
  if [ -x /usr/bin/landscape-sysinfo ]; then
# this is for Ubuntu
# don't try refresh this more than once per minute
# Due to cpu consumption and login delays (LP: #1893716)
stamp="/var/lib/landscape/landscape-sysinfo.cache"
NEED_UPDATE="FALSE"
[ -z "\$(find "\$stamp" -newermt 'now-1 minutes' 2> /dev/null)" ] && NEED_UPDATE="TRUE"

if [ "\$NEED_UPDATE" = "TRUE" ]; then
    # pam_motd does not carry the environment
    [ -f /etc/default/locale ] && . /etc/default/locale
    export LANG
    cores=\$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
    [ "\$cores" -eq "0" ] && cores=1
    threshold="\${cores:-1}.0"
    if [ \$(echo "`cut -f1 -d ' ' /proc/loadavg` < \$threshold" | bc) -eq 1 ]; then
        printf "\n\033[01m  System-Status (`/bin/date`)\033[0m\n\033[1;30m  ==================================================================\033[0m\n%s\n\033[1;30m  ==================================================================\033[0m\n" \\
            "\$(/usr/bin/landscape-sysinfo | sed '/Graph/d' | sed '/https/d' | sed '/^\s*$/d')" \\
#        printf "\n  System information as of %s\n\n%s\n" \\
#            "\$(/bin/date)" \\
#            "\$(/usr/bin/landscape-sysinfo)" \\
            > "\$stamp"
    else
        # do not replace a formerly good result due to load
        if ! grep -q "System information as of" \$stamp 2> /dev/null; then
            printf "\n System information disabled due to load higher than %s\n" "\$threshold" > "\$stamp"
        fi
    fi
fi

[ ! -r "\$stamp" ] || cat "\$stamp"
  else
# this is for Debian
    user=\$(whoami)
    lastlog=\`lastlog -u \${user} | grep -v Latest |  awk '{ printf \$5" "\$6" "\$7" "\$8" "\$9" from "\$3 }'\`
    date=\`date\`
    load=\`cat /proc/loadavg | awk '{print \$1" (1minute) "\$2" (5minutes) "\$3" (15minutes)"}'\`
    root_usage=\`df -h / | awk '/\// { percent=\$(NF-1); total=\$2 } END { print percent,"of",total }'\`
    root_used=\`df -h / | awk '/\// {print \$(NF-3)}'\`
    root_total=\`df -h / | awk '/\// {print \$(NF-2)}'\`
    memory=\`free -h | awk '/Mem|Speicher/ { print \$3"/"\$2 }'\`
    memory_usage=\`free -m | awk '/Mem|Speicher/ { total=\$2; used=\$3 } END { if (total>0){ printf("%3.1f%%", used/total*100) } else { printf("%3.1f%%", 0) } }'\`

    swap_usage=\`free -m | awk '/Swap:/ { total=\$2; used=\$3 } END { if (total>0){ printf("%3.1f%%", used/total*100) } else { printf("%3.1f%%", 0) } }'\`
    users=\`users | wc -w\`
    time=\`uptime | grep -ohe 'up .*' | sed 's/,/\ hours/g' | awk '{ printf \$2" "\$3 }'\`
    processes_total=\`ps aux | wc -l\`
    processes_user=\`ps -U \${user} u | wc -l\`

    #ip=\`ifconfig \$(route | grep default | awk '{ print \$8 }') | grep "inet" | awk '{print \$2}'\`
    ip=\`hostname -I | awk '{print \$1}'\`

    printf "\n\033[01m  System-Status (`/bin/date`)\033[0m\n\033[1;30m  ==================================================================\033[0m\n"
    echo -e "  Last Login:\t\t\$lastlog"
#       printf "  System load:\t\t%s\n  Usage of /:\t\t%s\n" \$load \$root_usage
    echo -e "  System load:\t\t\$load\n  Usage on /:\t\t\$root_used/\$root_total (\$root_usage)"
    printf "  Memory Usage:\t\t%s\n  Swap Usage:\t\t%s\n" "\$memory (\$memory_usage)" \$swap_usage
#       printf "  Usage On /:\t%s\tSwap Usage:\t%s\n" \$root_usage \$swap_usage
    printf "  Processes:\t\t%s\n  Users logged in:\t%s\n" "\$processes_total total, \$processes_user yours" \$users
    printf "  System Uptime:\t%s\n" "\$time"
    printf "  IP Address:\t\t%s\n" \$ip
    printf "\033[1;30m  ==================================================================\033[0m\n"
  fi
}

sysinfo
EOF
chmod +x /etc/update-motd.d/01-sysinfo

cat <<EOF >/etc/update-motd.d/02-updates
#!/bin/bash
#
#    02-updates - generate the update information
#    Copyright (C) 2023 Cornelius Rittner
#
#    Authors: Cornelius Rittner <rittner@wirth-horn.de>
#

updates(){
    if [ -x /usr/lib/update-notifier/update-motd-updates-available ]; then
        echo -e "\n\033[01m  Update Status:\033[0m"
        echo -e "\033[1;30m  ==================================================================\033[0m"
        stamp="/var/lib/update-notifier/updates-available"
        [ ! -r "\$stamp" ] || cat "\$stamp" | sed 's/^/  /g' | sed '/^\s*$/d'
        find \$stamp -newermt 'now-7 days' 2> /dev/null | grep -q -m 1 '.' || /usr/share/update-notifier/notify-updates-outdated | sed 's/^/  /g' | sed '/^\s*$/d'
        echo -e "\033[1;30m  ==================================================================\n\033[0m"
    else
        echo -e "\n\033[01m  Update Status:\033[0m"
        echo -e "\033[1;30m  ==================================================================\033[0m"
        echo -e "  \033[0;33m\$(apt list --upgradable 2>/dev/null | sed -E '/^(Auflistung.*|Listing.*)?$/d' | wc -l)\033[0m packages can be updated."
        echo -e "  \033[1;31m\$(apt list --upgradable 2>/dev/null | grep "\-security" | wc -l)\033[0m are security updates."
        echo -e "\033[1;30m  ==================================================================\n\033[0m"
    fi
}

updates
EOF
chmod +x /etc/update-motd.d/02-updates

# remove default motd 50-landscape-sysinfo -> /usr/share/landscape/landscape-sysinfo.wrapper
if [ -f /etc/update-motd.d/50-landscape-sysinfo ]; then
    rm /etc/update-motd.d/50-landscape-sysinfo
fi
# disable others
if [ -f /etc/update-motd.d/10-help-text ]; then
    chmod -x /etc/update-motd.d/10-help-text
fi
if [ -f /etc/update-motd.d/50-motd-news ]; then
    chmod -x /etc/update-motd.d/50-motd-news
fi
if [ -f /etc/update-motd.d/90-updates-available ]; then
    chmod -x /etc/update-motd.d/90-updates-available
fi
if [ -f /etc/update-motd.d/10-uname ]; then
    chmod -x /etc/update-motd.d/10-uname
fi

# Install IP Tables Firewall, use legacy version
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables
update-alternatives --set iptables /usr/sbin/iptables-legacy
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# create firewall rules
cat <<EOF >/etc/iptables.rules
*filter
# Create new chain
-N DOCKER-USER

# Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

# Accepts all established inbound connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allows all outbound traffic
# You could modify this to only allow certain traffic
-A OUTPUT -j ACCEPT

# Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow FTP connections from anywhere
-A INPUT -p tcp --dport 21 -j ACCEPT
-A INPUT -p tcp --match multiport --dports 50000:50100 -j ACCEPT

# Allows SSH connections
# The --dport number is the same as Port in /etc/ssh/sshd_config
-A INPUT -p tcp -m state --state NEW --dport 52022 -j ACCEPT

# Allows Munin connections (consider replace with Prometheus)
#-A INPUT -s 92.51.162.6 -p tcp --dport 4949 -j ACCEPT

# Allow ISPConfig connections
#-A INPUT -s 83.169.19.191 -p tcp -m state --state NEW --dport 8080 -j ACCEPT
# Allow Docker Portainer
#-A INPUT -s 83.169.19.191 -p tcp -m state --state NEW --dport 9443 -j ACCEPT

# Allow Nydus (Hosteurope)
-A INPUT -p tcp --dport 2224 -j ACCEPT

# Allows Postfix Traffic
#-A INPUT -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT

# Now you should read up on iptables rules and consider whether ssh access
# for everyone is really desired. Most likely you will only allow access from certain IPs.

# Allow ping
#  note that blocking other types of icmp packets is considered a bad idea by some
#  remove -m icmp --icmp-type 8 from this line to allow all kinds of icmp:
#  https://security.stackexchange.com/questions/22711
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# log iptables denied calls (access via 'dmesg' command)
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Reject all other inbound - default deny unless explicitly allowed policy:
-A INPUT -j REJECT
# Append forward to DOCKER-USER chain before REJECT
-A FORWARD -j DOCKER-USER
-A FORWARD -j REJECT

# Append DOCKER-USER chain filters
# Docker does the port-mapping in the PREROUTING chain of the nat table. This happens before the filter rules,
# so --dest and --dport will see the internal IP and port of the container.
# To access the original destination, you can use -m conntrack --ctorigdstport
# Allow Docker Portainer
#-A DOCKER-USER -s 83.169.19.191 -p tcp -m conntrack --ctorigdstport 9443 --ctdir ORIGINAL -j ACCEPT
# Drop all other traffic to Portainer
#-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 9443 --ctdir ORIGINAL -j DROP
-A DOCKER-USER -j RETURN

COMMIT
EOF

cat <<EOF >/etc/ip6tables.rules
*filter

# Allows all loopback (lo0) traffic and drop all traffic to ::1/128 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT ! -i lo -d ::1/128 -j REJECT

# Accepts all established inbound connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allows all outbound traffic
# You could modify this to only allow certain traffic
-A OUTPUT -j ACCEPT

# Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
#-A INPUT -p tcp --dport 80 -j ACCEPT
#-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow FTP connections from anywhere
#-A INPUT -p tcp --dport 21 -j ACCEPT
#-A INPUT -p tcp --match multiport --dports 50000:50100 -j ACCEPT

# Allow Nydus (Hosteurope)
-A INPUT -p tcp --dport 2224 -j ACCEPT

# Allow ping
#  note that blocking other types of icmp packets is considered a bad idea by some
#  remove -m icmp --icmp-type 8 from this line to allow all kinds of icmp:
#  https://security.stackexchange.com/questions/22711
-A INPUT -p ipv6-icmp --icmpv6-type 128 -j ACCEPT

# log ip6tables denied calls (access via 'dmesg' command)
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "ip6tables denied: " --log-level 7

# Reject all other inbound - default deny unless explicitly allowed policy:
-A INPUT -j REJECT
-A FORWARD -j REJECT

COMMIT
EOF

echo ""
echo "Applying SSH and firewall hardening changes..."

SSHD=/etc/ssh/sshd_config
TIMESTAMP=$(date +%F-%T)

# Backup sshd_config if not already backed up for this run
if [ ! -f "${SSHD}.backup-${TIMESTAMP}" ]; then
  cp -a "$SSHD" "${SSHD}.backup-${TIMESTAMP}"
  echo -e "${OK} Created backup of sshd_config: ${SSHD}.backup-${TIMESTAMP}"
fi

# helper to set or replace a directive in sshd_config (idempotent)
set_sshd_opt(){
  local opt="$1" value="$2" file="$SSHD"
  if grep -q -E "^[#[:space:]]*${opt}[[:space:]]+" "$file"; then
    sed -ri "s|^[#[:space:]]*${opt}[[:space:]]+.*/.*|${opt} ${value}|" "$file" && return 0 || return 1
  else
    echo "${opt} ${value}" >> "$file" && return 0 || return 1
  fi
}

changed=0
if set_sshd_opt Port 52022; then
  echo -e "${OK} Set SSH Port to 52022 in $SSHD"
  changed=1
else
  echo -e "${ERR} Failed to set Port in $SSHD"
fi

if set_sshd_opt PermitRootLogin prohibit-password; then
  echo -e "${OK} Set PermitRootLogin to prohibit-password in $SSHD"
  changed=1
else
  echo -e "${ERR} Failed to set PermitRootLogin in $SSHD"
fi

# Restart ssh only if we changed the config
if [ "$changed" -eq 1 ]; then
  if systemctl restart ssh 2>/dev/null; then
    echo -e "${OK} Restarted ssh service"
  else
    echo -e "${WARN} Could not restart ssh via systemctl; try: systemctl restart ssh or service ssh restart"
  fi
else
  echo -e "${WARN} No changes to sshd_config were required"
fi

# Install and configure UFW (idempotent)
if ! dpkg -s ufw >/dev/null 2>&1; then
  apt-get -y install ufw
  echo -e "${OK} Installed ufw"
else
  echo -e "${OK} ufw already installed"
fi

# Allow both the new SSH port and the default 22 to avoid accidental lockout. Admins may remove 22 later.
ufw allow 52022/tcp >/dev/null 2>&1 && echo -e "${OK} Allowed TCP 52022 through ufw"
ufw allow 22/tcp >/dev/null 2>&1 && echo -e "${WARN} Allowed TCP 22 through ufw (kept for safety; remove if you don't need it)"
ufw allow 80/tcp >/dev/null 2>&1 && echo -e "${OK} Allowed HTTP (80) through ufw"
ufw allow 443/tcp >/dev/null 2>&1 && echo -e "${OK} Allowed HTTPS (443) through ufw"
#ufw allow 2224/tcp >/dev/null 2>&1 && echo -e "${OK} Allowed TCP 2224 through ufw"

# Set sensible defaults
ufw default deny incoming >/dev/null 2>&1 && echo -e "${OK} Set ufw default to deny incoming"
ufw default allow outgoing >/dev/null 2>&1 && echo -e "${OK} Set ufw default to allow outgoing"

# Enable UFW non-interactively
if ufw status | grep -q inactive; then
  ufw --force enable >/dev/null 2>&1 && echo -e "${OK} ufw enabled"
else
  echo -e "${OK} ufw already enabled"
fi

echo ""
echo -e "${OK} sshd_config edits and ufw configuration applied."
echo -e "${WARN} Note: Port 22 is still allowed by UFW to avoid locking you out; remove it when you verified SSH on port 52022 works: ufw delete allow 22/tcp"
#echo -e "${WARN} iptables rules in /etc/iptables.rules and /etc/ip6tables.rules were left untouched. If you prefer to use only UFW, review or remove those files."

echo -e "\nTo revert the sshd_config changes, restore the backup:\n  cp -a ${SSHD}.backup-${TIMESTAMP} ${SSHD} && systemctl restart ssh"

echo -e "\nIf you want to persist iptables rules or use iptables-persistent instead of UFW:\n  apt-get install iptables-persistent\n  iptables-save > /etc/iptables/rules.v4\n  ip6tables-save > /etc/iptables/rules.v6"

echo "Done."
echo "--------------------------------------------------"
echo -e "${OK} Virtual Private Server Bootstrap finished"
echo "Restart your terminal session (logout and relogin)"
echo "--------------------------------------------------"
