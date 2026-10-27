#!/usr/bin/env bash
# Build and install rizin (shared libraries) and the rz-ghidra decompiler
# plugin from source, as docs/install.md describes — for a Linux host whose
# package manager has no current rizin (Ubuntu 24.04 has none at all).
#
# Why from source: rizin's portable static release build cannot load plugins
# (it is a fully static executable with no shared librz to load a .so into),
# so rz-ghidra needs a shared rizin. rz-ghidra publishes no Linux binaries.
#
# Idempotent: when the wanted rizin is already on PATH and loads rz-ghidra, it
# exits at once, so it is safe as an environment setup script or a session
# start hook. A full build takes about 6 minutes on 4 cores.
#
#   scripts/install-rizin.sh                 # into /usr/local (sudo if needed)
#   PREFIX=$HOME/.local scripts/install-rizin.sh
#   WITH_GHIDRA=0 scripts/install-rizin.sh   # rizin only
#
# Needs: a C/C++ toolchain, meson, ninja, cmake, pkg-config, git, curl, and the
# zlib headers. With INSTALL_DEPS=1 on an apt-based system it installs the
# missing ones itself (as root, or through sudo).
set -euo pipefail

RIZIN_VERSION="${RIZIN_VERSION:-0.9.1}"
# rz-ghidra's tags track rizin's minor version: v0.9.0 builds against rizin 0.9.x.
RZ_GHIDRA_VERSION="${RZ_GHIDRA_VERSION:-0.9.0}"
PREFIX="${PREFIX:-/usr/local}"
WITH_GHIDRA="${WITH_GHIDRA:-1}"
INSTALL_DEPS="${INSTALL_DEPS:-0}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

log() { printf 'install-rizin: %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "this script builds on Linux only; see docs/install.md for macOS and Windows"

RIZIN="$PREFIX/bin/rizin"

# Run a command as root when the prefix is not writable by us.
as_owner() {
	if [ -w "$PREFIX" ] || { [ ! -e "$PREFIX" ] && [ -w "$(dirname "$PREFIX")" ]; }; then
		"$@"
	elif [ "$(id -u)" = 0 ]; then
		"$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo "$@"
	else
		die "$PREFIX is not writable and sudo is unavailable; set PREFIX to a directory you own"
	fi
}

have_rizin() {
	[ -x "$RIZIN" ] && "$RIZIN" -v 2>/dev/null | head -1 | grep -q "^rizin $RIZIN_VERSION "
}

have_ghidra() {
	"$RIZIN" -N -qc 'Lc' -- 2>/dev/null | grep -q '^ghidra'
}

if have_rizin && { [ "$WITH_GHIDRA" != 1 ] || have_ghidra; }; then
	log "rizin $RIZIN_VERSION$([ "$WITH_GHIDRA" = 1 ] && echo " with rz-ghidra") is already installed in $PREFIX"
	exit 0
fi

# --- build dependencies ---
missing=()
for tool in cc c++ meson ninja cmake pkg-config git curl; do
	command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
[ -f /usr/include/zlib.h ] || missing+=("zlib-headers")
if [ "${#missing[@]}" -gt 0 ]; then
	if [ "$INSTALL_DEPS" = 1 ] && command -v apt-get >/dev/null 2>&1; then
		log "installing build dependencies (${missing[*]})"
		sudo_cmd=()
		[ "$(id -u)" = 0 ] || sudo_cmd=(sudo)
		"${sudo_cmd[@]}" apt-get update -qq
		"${sudo_cmd[@]}" apt-get install -y -qq build-essential meson ninja-build cmake pkg-config git curl zlib1g-dev
	else
		die "missing build dependencies: ${missing[*]} (install them, or rerun with INSTALL_DEPS=1 on an apt-based system)"
	fi
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/install-rizin.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# --- rizin, from its source release (which vendors every meson subproject, so the build fetches nothing else) ---
if ! have_rizin; then
	log "building rizin $RIZIN_VERSION into $PREFIX"
	curl -fsSL "https://github.com/rizinorg/rizin/releases/download/v${RIZIN_VERSION}/rizin-src-v${RIZIN_VERSION}.tar.xz" -o "$WORK/rizin-src.tar.xz"
	tar -xJf "$WORK/rizin-src.tar.xz" -C "$WORK"
	src="$WORK/rizin-v${RIZIN_VERSION}"
	meson setup "$src/build" "$src" --prefix="$PREFIX" --buildtype=release >"$WORK/rizin-meson.log" 2>&1 ||
		{ tail -30 "$WORK/rizin-meson.log" >&2; die "meson setup failed"; }
	ninja -C "$src/build" -j "$JOBS" >"$WORK/rizin-ninja.log" 2>&1 ||
		{ tail -30 "$WORK/rizin-ninja.log" >&2; die "rizin build failed"; }
	as_owner ninja -C "$src/build" install >"$WORK/rizin-install.log" 2>&1 ||
		{ tail -30 "$WORK/rizin-install.log" >&2; die "rizin install failed"; }
	# A system prefix needs the loader cache refreshed to find the new librz libraries.
	case "$PREFIX" in /usr | /usr/local) as_owner ldconfig ;; esac
	have_rizin || die "rizin $RIZIN_VERSION did not install to $RIZIN"
fi

# --- rz-ghidra, against that rizin ---
if [ "$WITH_GHIDRA" = 1 ] && ! have_ghidra; then
	log "building rz-ghidra v$RZ_GHIDRA_VERSION against $RIZIN"
	git clone -q --depth 1 --branch "v${RZ_GHIDRA_VERSION}" --recurse-submodules --shallow-submodules \
		https://github.com/rizinorg/rz-ghidra.git "$WORK/rz-ghidra" 2>"$WORK/rz-ghidra-clone.log" ||
		{ tail -20 "$WORK/rz-ghidra-clone.log" >&2; die "could not clone rz-ghidra"; }
	cmake -S "$WORK/rz-ghidra" -B "$WORK/rz-ghidra/build" -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_PREFIX_PATH="$PREFIX" -DCMAKE_INSTALL_PREFIX="$("$RIZIN" -H RZ_PREFIX)" \
		-DBUILD_CUTTER_PLUGIN=OFF -DBUILD_SLEIGH_PLUGIN=OFF >"$WORK/rz-ghidra-cmake.log" 2>&1 ||
		{ tail -30 "$WORK/rz-ghidra-cmake.log" >&2; die "rz-ghidra cmake failed"; }
	cmake --build "$WORK/rz-ghidra/build" -j "$JOBS" >"$WORK/rz-ghidra-build.log" 2>&1 ||
		{ tail -30 "$WORK/rz-ghidra-build.log" >&2; die "rz-ghidra build failed"; }
	as_owner cmake --install "$WORK/rz-ghidra/build" >"$WORK/rz-ghidra-install.log" 2>&1 ||
		{ tail -30 "$WORK/rz-ghidra-install.log" >&2; die "rz-ghidra install failed"; }
	have_ghidra || die "rz-ghidra built but $RIZIN does not load it (expected in $("$RIZIN" -H RZ_LIB_PLUGINS))"
fi

log "$("$RIZIN" -v | head -1)$([ "$WITH_GHIDRA" = 1 ] && echo " + rz-ghidra v$RZ_GHIDRA_VERSION") installed in $PREFIX"
case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) log "note: $PREFIX/bin is not on PATH — add it, or set OMPRE_RIZIN_PATH=$RIZIN" ;; esac
