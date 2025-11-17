#!/usr/bin/env bash
set -euo pipefail

### NOTES ###################################################################
# Script to build and install Icinga 1.14.2 from source in a "Debian-style"
# layout (paths, users, permissions, systemd unit) similar to the old
# Debian icinga 1.x packages.
#
# Tested on:
#   - Debian Trixie (AArch64 / 64-bit ARM)
#
# Intended for a fresh system where no icinga packages from the Debian
# archive are installed. It will write to:
#   - /etc/icinga
#   - /var/lib/icinga
#   - /var/log/icinga

### CONFIG ###################################################################

ICINGA_VERSION_TAG="v1.14.2"
SRC_DIR="/usr/local/src"
ICINGA_SRC="${SRC_DIR}/icinga-core"

### FUNCTIONS ################################################################

find_free_id() {
  # Find a free numeric ID (for UID/GID) starting from 100 upwards
  local id
  for id in $(seq 100 999); do
    if ! getent passwd "${id}" >/dev/null && ! getent group "${id}" >/dev/null; then
      echo "${id}"
      return 0
    fi
  done
  echo "No free UID/GID found in 100–999 range" >&2
  exit 1
}

ensure_nagios_user_group() {
  local uid gid

  if getent group nagios >/dev/null; then
    gid=$(getent group nagios | cut -d: -f3)
    echo "Group 'nagios' already exists with GID=${gid}"
  else
    gid=$(find_free_id)
    echo "Creating group 'nagios' with GID=${gid}"
    groupadd -g "${gid}" nagios
  fi

  if getent passwd nagios >/dev/null; then
    uid=$(getent passwd nagios | cut -d: -f3)
    echo "User 'nagios' already exists with UID=${uid}"
  else
    # Prefer matching UID=GID if free, else find another
    if getent passwd "${gid}" >/dev/null; then
      uid=$(find_free_id)
    else
      uid="${gid}"
    fi
    echo "Creating user 'nagios' with UID=${uid}, GID=${gid}"
    useradd -r -u "${uid}" -g "${gid}" -d /var/lib/icinga -s /usr/sbin/nologin nagios
  fi

  # Ensure www-data is in the 'nagios' group (for external command pipe access)
  if id -nG www-data 2>/dev/null | grep -qw nagios; then
    echo "User 'www-data' already in group 'nagios'"
  else
    echo "Adding 'www-data' to group 'nagios'"
    usermod -a -G nagios www-data
  fi
}

### PRECHECK #################################################################

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run this script as root." >&2
  exit 1
fi

echo "=== Icinga 1.14.2 build & install (Debian-style) starting ==="

### 1. USER/GROUP ############################################################

ensure_nagios_user_group

### 2. PACKAGES ##############################################################

echo "=== Installing build and runtime dependencies ==="
apt-get update
apt-get install -y git build-essential autoconf automake libtool pkg-config \
  libgd-dev libjpeg-dev libpng-dev libssl-dev zlib1g-dev \
  apache2 apache2-utils monitoring-plugins-basic
  # use monitoring-plugins for additional plugins

### 3. FETCH SOURCE ##########################################################

echo "=== Fetching Icinga core source ==="
mkdir -p "${SRC_DIR}"
cd "${SRC_DIR}"

if [[ -d "${ICINGA_SRC}" ]]; then
  echo "Source dir ${ICINGA_SRC} already exists, reusing it"
  cd "${ICINGA_SRC}"
  git fetch --all --tags
else
  git clone https://github.com/Icinga/icinga-core.git
  cd "${ICINGA_SRC}"
fi

git checkout "${ICINGA_VERSION_TAG}"
make distclean >/dev/null 2>&1 || true

### 4. CONFIGURE #############################################################

echo "=== Configuring Icinga ==="
CFLAGS="-O2 -g -fcommon -Dsmb_snprintf=snprintf -Dsmb_vsnprintf=vsnprintf" \
./configure \
  --prefix=/usr \
  --sysconfdir=/etc/icinga \
  --localstatedir=/var/lib/icinga \
  --datarootdir=/usr/share/icinga \
  --bindir=/usr/bin \
  --sbindir=/usr/lib/cgi-bin/icinga \
  --libdir=/usr/lib \
  --libexecdir=/usr/lib/nagios/plugins \
  --with-icinga-user=nagios \
  --with-icinga-group=nagios \
  --with-command-user=www-data \
  --with-command-group=nagios \
  --with-log-dir=/var/log/icinga \
  --with-checkresult-dir=/var/lib/icinga/spool/checkresults \
  --with-temp-dir=/var/lib/icinga/tmp \
  --with-temp-file=/var/lib/icinga/icinga.tmp \
  --with-ext-cmd-file-dir=/var/lib/icinga/rw \
  --with-lockfile=/var/lib/icinga/icinga.lock \
  --with-icinga-chkfile=/var/lib/icinga/icinga.chk \
  --with-httpd-conf=/etc/apache2/conf-available \
  --with-cgiurl=/icinga/cgi-bin \
  --with-htmurl=/icinga \
  --with-mainurl='/icinga/cgi-bin/status.cgi?host=all&style=detail&sortobject=services&sorttype=2&sortoption=3' \
  --disable-idoutils

### 5. BUILD #################################################################

echo "=== Building Icinga core and CGIs ==="
make -j"$(nproc)" icinga cgis

### 6. INSTALL CORE + CGIs + HTML ###########################################

echo "=== Installing core, CGIs and HTML ==="
make install-base
make install-cgis
make install-html

### 7. INSTALL CONFIG ########################################################

echo "=== Installing upstream config to /etc/icinga ==="
make install-config CFGDIR=/etc/icinga INSTALL_OPTS="-o nagios -g nagios"

echo "=== Setting date format to European style ==="
sed -i \
 -e 's|^date_format=.*|date_format=euro|' \
/etc/icinga/icinga.cfg

echo "=== Fixing /etc/icinga ownership and permissions ==="
chown -R root:nagios /etc/icinga
find /etc/icinga -type f -exec chmod 640 {} \;
chmod 750 /etc/icinga

echo "=== Installing p1.pl into /usr/lib ==="
install -m 755 -o root -g nagios /usr/local/src/icinga-core/p1.pl /usr/lib/p1.pl

### 8. DIRECTORIES UNDER /var ################################################

echo "=== Ensuring /var/lib/icinga and /var/log/icinga exist ==="
install -d -m 775 -o nagios -g nagios /var/lib/icinga
install -d -m 775 -o www-data -g nagios /var/lib/icinga/rw
install -d -m 775 -o nagios -g nagios /var/lib/icinga/tmp
install -d -m 775 -o nagios -g nagios /var/lib/icinga/spool/checkresults
install -d -m 755 -o nagios -g nagios /var/log/icinga

### 9. COMMANDMODE + APACHE ##################################################

echo "=== Installing commandmode (external command pipe) ==="
make install-commandmode

echo "=== Installing Apache web config ==="
make install-webconf
a2enmod cgid
a2enconf icinga
systemctl reload apache2

### 10. /etc/default/icinga ##################################################

echo "=== Writing /etc/default/icinga ==="
tee /etc/default/icinga > /dev/null << 'EOF'
# Validate configuration before starting Icinga
ICINGA_VERIFY_OPTS="-v /etc/icinga/icinga.cfg"

# Run Icinga in daemon mode with the main config file
ICINGA_OPTS="-d /etc/icinga/icinga.cfg"
EOF

### 11. SYSTEMD UNIT #########################################################

echo "=== Writing systemd unit /etc/systemd/system/icinga.service ==="
tee /etc/systemd/system/icinga.service > /dev/null << 'EOF'
[Unit]
Description=Icinga Open-Source Monitoring System
Documentation=man:icinga(8)
After=network.target

[Service]
Type=forking
User=nagios
Group=nagios
EnvironmentFile=-/etc/default/icinga

# Validate config before startup
ExecStartPre=/usr/bin/icinga $ICINGA_VERIFY_OPTS

# Start daemon (Icinga will fork)
ExecStart=/usr/bin/icinga $ICINGA_OPTS

ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

### 12. PRE-FLIGHT CHECK #####################################################

echo "=== Running pre-flight check as nagios ==="
su -s /bin/sh -c '/usr/bin/icinga -v /etc/icinga/icinga.cfg' nagios

### 13. ENABLE + START SERVICE ###############################################

echo "=== Enabling and starting icinga.service ==="
systemctl enable --now icinga
systemctl status icinga --no-pager || true

echo "=== Icinga 1.14.2 installation completed ==="
echo
echo "Next steps:"
echo "  1) Create a web UI user:"
echo "       htpasswd -bc /etc/icinga/htpasswd.users icingaadmin YourPassword"
echo "  2) Reload Apache:"
echo "       systemctl reload apache2"
echo
echo "Then open the Classic UI at:  http://<this-host>/icinga/"
