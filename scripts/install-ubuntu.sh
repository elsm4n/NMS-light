#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO_URL="https://github.com/elsm4n/NMS-light.git"
readonly APP_DIR="/etc/rust-nms"
readonly ENV_FILE="/etc/rust-nms/app.env"
readonly UNIT_FILE="/etc/systemd/system/rust-nms.service"
readonly APP_BIN="/usr/local/bin/rust-nms"
readonly DB_ROLE="rust_nms"
readonly DB_NAME="rust_nms"
readonly BUILD_DB="rust_nms_build"
readonly SERVICE_USER="rust-nms"
readonly PG_VERSION="17"

WORK_DIR=""
PG_CLUSTER=""
PG_PORT=""
DB_ROLE_CREATED=0
BUILD_DB_CREATED=0
APP_DB_CREATED=0
ENV_FILE_CREATED=0
APP_DIR_CREATED=0
UNIT_FILE_CREATED=0
APP_BIN_CREATED=0
SERVICE_USER_CREATED=0
COMPLETE=0
DB_PASSWORD=""

log() { printf '[rust-nms] %s\n' "$*"; }
die() { printf '[rust-nms] ERROR: %s\n' "$*" >&2; exit 1; }
as_root() {
    if (( EUID == 0 )); then
        "$@"
    else
        sudo "$@"
    fi
}

pg_admin() {
    if (( EUID == 0 )); then
        runuser -u postgres -- "/usr/lib/postgresql/${PG_VERSION}/bin/psql" \
            -X -v ON_ERROR_STOP=1 -h /var/run/postgresql -p "$PG_PORT" "$@"
    else
        sudo -u postgres "/usr/lib/postgresql/${PG_VERSION}/bin/psql" \
            -X -v ON_ERROR_STOP=1 -h /var/run/postgresql -p "$PG_PORT" "$@"
    fi
}

cleanup() {
    local exit_code=$1
    trap - EXIT
    if (( exit_code != 0 && COMPLETE == 0 )); then
        if (( DB_ROLE_CREATED || BUILD_DB_CREATED || APP_DB_CREATED || ENV_FILE_CREATED || APP_DIR_CREATED || UNIT_FILE_CREATED || APP_BIN_CREATED || SERVICE_USER_CREATED )); then
            log "Pemasangan gagal; membersihkan database dan file aplikasi yang dibuat oleh proses ini."
        fi
        if (( UNIT_FILE_CREATED )); then as_root systemctl disable --now rust-nms.service >/dev/null 2>&1 || true; fi
        if [[ -n "$PG_CLUSTER" && -n "$PG_PORT" ]] && command -v pg_lsclusters >/dev/null 2>&1; then
            if (( APP_DB_CREATED )); then
                pg_admin -d postgres -q -c "DROP DATABASE IF EXISTS \"$DB_NAME\";" >/dev/null 2>&1 || true
            fi
            if (( BUILD_DB_CREATED )); then
                pg_admin -d postgres -q -c "DROP DATABASE IF EXISTS \"$BUILD_DB\";" >/dev/null 2>&1 || true
            fi
            if (( DB_ROLE_CREATED )); then
                pg_admin -d postgres -q -c "DROP ROLE IF EXISTS \"$DB_ROLE\";" >/dev/null 2>&1 || true
            fi
        fi
        if (( UNIT_FILE_CREATED )); then as_root rm -f "$UNIT_FILE"; fi
        if (( ENV_FILE_CREATED )); then as_root rm -f "$ENV_FILE"; fi
        if (( APP_DIR_CREATED )); then as_root rmdir "$APP_DIR" >/dev/null 2>&1 || true; fi
        if (( APP_BIN_CREATED )); then as_root rm -f "$APP_BIN"; fi
        if (( SERVICE_USER_CREATED )); then as_root userdel --remove "$SERVICE_USER" >/dev/null 2>&1 || true; fi
        if (( UNIT_FILE_CREATED )); then as_root systemctl daemon-reload >/dev/null 2>&1 || true; fi
    fi
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then rm -rf "$WORK_DIR"; fi
    exit "$exit_code"
}
trap 'cleanup $?' EXIT

show_help() {
    cat <<'EOF'
Installer Rust NMS untuk Ubuntu 22.04/24.04.

Jalankan dari terminal interaktif:
  curl -fsSL https://raw.githubusercontent.com/elsm4n/NMS-light/main/scripts/install-ubuntu.sh | bash

Skrip meminta email dan kata sandi admin awal, lalu memasang PostgreSQL 17,
TimescaleDB, aplikasi, serta layanan systemd. Diperlukan akses sudo dan internet.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    show_help
    exit 0
fi

[[ -t 2 ]] || die "Jalankan dari terminal interaktif agar kredensial admin dapat dimasukkan dengan aman."
[[ -r /dev/tty ]] || die "Terminal interaktif (/dev/tty) tidak tersedia."

if (( EUID != 0 )); then
    command -v sudo >/dev/null 2>&1 || die "sudo tidak ditemukan; jalankan sebagai root atau pasang sudo."
    sudo -v || die "Otorisasi sudo diperlukan untuk memasang paket dan layanan sistem."
fi

[[ -r /etc/os-release ]] || die "Sistem operasi tidak dikenali; installer ini hanya mendukung Ubuntu 22.04/24.04."
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" && ( "${VERSION_ID:-}" == "22.04" || "${VERSION_ID:-}" == "24.04" ) ]] || \
    die "Versi tidak didukung (${PRETTY_NAME:-unknown}); gunakan Ubuntu 22.04 atau 24.04."

for command_name in apt-get dpkg curl; do
    command -v "$command_name" >/dev/null 2>&1 || die "Perintah wajib tidak ditemukan: $command_name"
done

for existing_path in "$ENV_FILE" "$UNIT_FILE" "$APP_BIN"; do
    [[ ! -e "$existing_path" ]] || die "Ditemukan instalasi/file yang sudah ada: $existing_path. Installer tidak akan menimpanya."
done
[[ ! -e "$APP_DIR" ]] || die "Direktori $APP_DIR sudah ada. Installer tidak akan mengubahnya."
[[ ! -e /var/lib/rust-nms ]] || die "Direktori /var/lib/rust-nms sudah ada. Installer tidak akan mengubahnya."
if getent passwd "$SERVICE_USER" >/dev/null; then
    die "Akun sistem $SERVICE_USER sudah ada. Installer tidak akan mengubahnya."
fi
if command -v pg_lsclusters >/dev/null 2>&1 && pg_lsclusters --no-header 2>/dev/null | awk '$1 == "17" { found=1 } END { exit !found }'; then
    die "Cluster PostgreSQL 17 sudah ada. Installer tidak akan mengubah cluster atau database yang sudah terpasang."
fi
if timeout 1 bash -c '</dev/tcp/127.0.0.1/8080' 2>/dev/null; then
    die "Port 127.0.0.1:8080 sudah digunakan. Bebaskan port tersebut sebelum instalasi."
fi

admin_email=""
admin_password=""
admin_password_confirm=""
while :; do
    read -r -p "Email admin awal: " admin_email </dev/tty
    if [[ "$admin_email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then break; fi
    printf 'Format email tidak valid.\n' >&2
done
while :; do
    read -r -s -p "Kata sandi admin (minimal 16 karakter): " admin_password </dev/tty
    printf '\n' >/dev/tty
    read -r -s -p "Ulangi kata sandi admin: " admin_password_confirm </dev/tty
    printf '\n' >/dev/tty
    if (( ${#admin_password} < 16 )); then
        printf 'Kata sandi harus minimal 16 karakter.\n' >&2
    elif [[ "$admin_password" != "$admin_password_confirm" ]]; then
        printf 'Kata sandi tidak sama.\n' >&2
    else
        break
    fi
done
unset admin_password_confirm

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rust-nms-install.XXXXXX")
chmod 700 "$WORK_DIR"

ensure_rust() {
    local current_version=""
    local major=0 minor=0
    if command -v rustc >/dev/null 2>&1; then
        current_version=$(rustc --version | awk '{print $2}')
        IFS=. read -r major minor _ <<< "$current_version"
    fi
    if (( major > 1 || (major == 1 && minor >= 94) )) && command -v cargo >/dev/null 2>&1; then
        log "Memakai Rust $current_version yang sudah tersedia."
        return
    fi

    if ! command -v rustup >/dev/null 2>&1; then
        log "Memasang rustup dan toolchain Rust stable (minimal 1.94)."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    command -v rustup >/dev/null 2>&1 || die "rustup tidak dapat dipasang atau tidak ditemukan."
    rustup toolchain install stable --profile minimal
    export RUSTUP_TOOLCHAIN=stable
    current_version=$(rustup run stable rustc --version | awk '{print $2}')
    IFS=. read -r major minor _ <<< "$current_version"
    (( major > 1 || (major == 1 && minor >= 94) )) || die "Toolchain Rust $current_version lebih lama daripada 1.94."
}

ensure_rust

log "Memasang tool build serta menambahkan repository resmi PostgreSQL dan TimescaleDB."
as_root apt-get update
as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl git gnupg openssl build-essential pkg-config postgresql-common

codename=${VERSION_CODENAME:-}
[[ -n "$codename" ]] || die "VERSION_CODENAME tidak ditemukan pada /etc/os-release."
architecture=$(dpkg --print-architecture)

as_root install -d -m 0755 /usr/share/postgresql-common/pgdg /usr/share/keyrings
if [[ ! -s /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc ]]; then
    curl --proto '=https' --tlsv1.2 -fsSLo "$WORK_DIR/apt.postgresql.org.asc" \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc
    as_root install -m 0644 "$WORK_DIR/apt.postgresql.org.asc" \
        /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
fi
if [[ ! -e /etc/apt/sources.list.d/rust-nms-pgdg.sources ]]; then
    cat > "$WORK_DIR/rust-nms-pgdg.sources" <<EOF
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: ${codename}-pgdg
Architectures: ${architecture}
Components: main
Signed-By: /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
EOF
    as_root install -m 0644 "$WORK_DIR/rust-nms-pgdg.sources" /etc/apt/sources.list.d/rust-nms-pgdg.sources
fi

curl --proto '=https' --tlsv1.2 -fsSLo "$WORK_DIR/timescaledb.asc" \
    https://packagecloud.io/timescale/timescaledb/gpgkey
gpg --batch --dearmor --yes -o "$WORK_DIR/rust-nms-timescaledb.gpg" "$WORK_DIR/timescaledb.asc"
as_root install -m 0644 "$WORK_DIR/rust-nms-timescaledb.gpg" /usr/share/keyrings/rust-nms-timescaledb.gpg
cat > "$WORK_DIR/rust-nms-timescaledb.list" <<EOF
deb [signed-by=/usr/share/keyrings/rust-nms-timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/ubuntu/ ${codename} main
EOF
as_root install -m 0644 "$WORK_DIR/rust-nms-timescaledb.list" /etc/apt/sources.list.d/rust-nms-timescaledb.list

as_root apt-get update
candidate=$(apt-cache policy "timescaledb-2-postgresql-${PG_VERSION}" | awk '/Candidate:/ { print $2; exit }')
[[ -n "$candidate" && "$candidate" != "(none)" ]] || die "Paket TimescaleDB untuk PostgreSQL ${PG_VERSION} tidak tersedia pada Ubuntu/arsitektur ini."
as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    "postgresql-${PG_VERSION}" "postgresql-client-${PG_VERSION}" "timescaledb-2-postgresql-${PG_VERSION}"

if ! command -v pg_lsclusters >/dev/null 2>&1; then
    die "Utilitas pg_lsclusters tidak ditemukan setelah PostgreSQL dipasang."
fi
cluster_line=$(pg_lsclusters --no-header | awk '$1 == "17" { print; exit }')
if [[ -z "$cluster_line" ]]; then
    as_root pg_createcluster "$PG_VERSION" main --start
    cluster_line=$(pg_lsclusters --no-header | awk '$1 == "17" { print; exit }')
fi
[[ -n "$cluster_line" ]] || die "Cluster PostgreSQL 17 tidak berhasil dibuat."
read -r _ PG_CLUSTER PG_PORT cluster_status _ <<< "$cluster_line"
if [[ "$cluster_status" != "online" ]]; then
    as_root pg_ctlcluster "$PG_VERSION" "$PG_CLUSTER" start
fi

PG_ISREADY="/usr/lib/postgresql/${PG_VERSION}/bin/pg_isready"
[[ -x "$PG_ISREADY" ]] || die "pg_isready PostgreSQL ${PG_VERSION} tidak ditemukan."
"$PG_ISREADY" -h /var/run/postgresql -p "$PG_PORT" >/dev/null || die "PostgreSQL ${PG_VERSION} belum siap."

preload=$(pg_admin -d postgres -Atqc 'SHOW shared_preload_libraries;')
case ",${preload//[[:space:]]/}," in
    *,timescaledb,*) ;;
    *)
        preload_updated="${preload:+${preload},}timescaledb"
        pg_admin -d postgres -v preload="$preload_updated" \
            -c "ALTER SYSTEM SET shared_preload_libraries TO :'preload';" >/dev/null
        as_root pg_ctlcluster "$PG_VERSION" "$PG_CLUSTER" restart
        ;;
esac

role_exists=$(pg_admin -d postgres -Atqc "SELECT 1 FROM pg_roles WHERE rolname = '${DB_ROLE}';")
db_exists=$(pg_admin -d postgres -Atqc "SELECT 1 FROM pg_database WHERE datname IN ('${DB_NAME}', '${BUILD_DB}');")
[[ -z "$role_exists" && -z "$db_exists" ]] || die "Role/database rust_nms sudah ada di cluster ini; installer berhenti agar tidak menimpa data."
DB_PASSWORD=$(openssl rand -hex 24)
pg_admin -d postgres -c "CREATE ROLE ${DB_ROLE} LOGIN PASSWORD '${DB_PASSWORD}';" >/dev/null
DB_ROLE_CREATED=1

# Build against a temporary schema because SQLx query macros inspect DATABASE_URL at compile time.
pg_admin -d postgres -c "CREATE DATABASE ${BUILD_DB} OWNER ${DB_ROLE};" >/dev/null
BUILD_DB_CREATED=1
pg_admin -d "$BUILD_DB" -c 'CREATE EXTENSION IF NOT EXISTS timescaledb;' >/dev/null
cat > "$WORK_DIR/pgpass" <<EOF
127.0.0.1:${PG_PORT}:*:${DB_ROLE}:${DB_PASSWORD}
EOF
chmod 0600 "$WORK_DIR/pgpass"
export PGPASSFILE="$WORK_DIR/pgpass"

log "Mengambil kode sumber dan menerapkan migrasi pada database sementara untuk pemeriksaan SQLx."
git clone --depth 1 --branch main "$REPO_URL" "$WORK_DIR/src"
for migration in "$WORK_DIR"/src/migrations/*.sql; do
    psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PG_PORT" \
        -U "$DB_ROLE" -d "$BUILD_DB" -f "$migration" >/dev/null
done
BUILD_DATABASE_URL="postgresql://${DB_ROLE}:${DB_PASSWORD}@127.0.0.1:${PG_PORT}/${BUILD_DB}"
log "Membangun binary release; kompilasi dapat memerlukan beberapa menit."
(
    cd "$WORK_DIR/src"
    env -u SQLX_OFFLINE DATABASE_URL="$BUILD_DATABASE_URL" cargo build --locked --release
)

pg_admin -d postgres -c "DROP DATABASE ${BUILD_DB};" >/dev/null
BUILD_DB_CREATED=0
pg_admin -d postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_ROLE};" >/dev/null
APP_DB_CREATED=1
pg_admin -d "$DB_NAME" -c 'CREATE EXTENSION IF NOT EXISTS timescaledb;' >/dev/null

as_root useradd --system --home-dir /var/lib/rust-nms --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
SERVICE_USER_CREATED=1
as_root install -D -m 0755 "$WORK_DIR/src/target/release/rust-nms" "$APP_BIN"
APP_BIN_CREATED=1

systemd_quote() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '"%s"' "$value"
}
cat > "$WORK_DIR/app.env" <<EOF
NMS_DATABASE_URL=postgresql://${DB_ROLE}:${DB_PASSWORD}@127.0.0.1:${PG_PORT}/${DB_NAME}
NMS_LISTEN_ADDR=127.0.0.1:8080
NMS_JWT_SECRET=$(openssl rand -hex 32)
NMS_CREDENTIAL_KEY_HEX=$(openssl rand -hex 32)
NMS_BOOTSTRAP_ADMIN_EMAIL=$(systemd_quote "$admin_email")
NMS_BOOTSTRAP_ADMIN_PASSWORD=$(systemd_quote "$admin_password")
EOF
unset admin_password
as_root install -d -o root -g "$SERVICE_USER" -m 0750 "$APP_DIR"
APP_DIR_CREATED=1
as_root install -o root -g "$SERVICE_USER" -m 0640 "$WORK_DIR/app.env" "$ENV_FILE"
ENV_FILE_CREATED=1

cat > "$WORK_DIR/rust-nms.service" <<'EOF'
[Unit]
Description=Rust NMS network monitoring service
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=rust-nms
Group=rust-nms
WorkingDirectory=/var/lib/rust-nms
EnvironmentFile=/etc/rust-nms/app.env
ExecStart=/usr/local/bin/rust-nms
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF
as_root install -m 0644 "$WORK_DIR/rust-nms.service" "$UNIT_FILE"
UNIT_FILE_CREATED=1
as_root systemctl daemon-reload
as_root systemctl enable --now rust-nms.service

log "Menunggu migrasi aplikasi dan endpoint health."
ready=0
for _ in $(seq 1 60); do
    if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/health/ready >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done
(( ready == 1 )) || {
    as_root systemctl status --no-pager rust-nms.service >&2 || true
    as_root journalctl -u rust-nms.service -n 50 --no-pager >&2 || true
    die "Aplikasi tidak menjadi ready. Periksa log di atas sebelum mencoba ulang."
}

# Bootstrap credentials are needed only once; remove them from the persistent service environment.
as_root sed -i '/^NMS_BOOTSTRAP_ADMIN_EMAIL=/d; /^NMS_BOOTSTRAP_ADMIN_PASSWORD=/d' "$ENV_FILE"
as_root systemctl restart rust-nms.service
ready=0
for _ in $(seq 1 30); do
    if curl --fail --silent --max-time 2 http://127.0.0.1:8080/health/ready >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done
(( ready == 1 )) || die "Layanan tidak kembali ready setelah penghapusan kredensial bootstrap."

COMPLETE=1
log "Instalasi selesai. Layanan: systemctl status rust-nms"
log "API lokal: http://127.0.0.1:8080 (health: /health/ready)"
log "Admin awal: ${admin_email}; gunakan kata sandi yang dimasukkan saat instalasi."
log "Discovery tetap nonaktif; ubah NMS_DISCOVERY_CIDRS di ${ENV_FILE} hanya untuk CIDR yang Anda kelola."
