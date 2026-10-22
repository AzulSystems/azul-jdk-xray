#!/bin/sh
# Azul JDK X-Ray Tool for macOS / Linux.
# Version 1.2.0
#
# Copyright (c) 2026, Azul Systems, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# See the LICENSE file in the project root for the full license text.
# Run:  sh azul-jdk-xray.sh
# Exit: 0 - no exposure found | 1 - outdated Java found | 2 - undetermined | 3 no Java found

# ---- VERSION TABLE ----
# <feature release>:<minimum acceptable patch level>
# A patch level may carry a CSPU revision: 12.1 means 21.0.12.1, which ranks
# above 21.0.12. OpenJDK ships CSPUs between quarterly CPUs, so this table
# goes stale monthly, not quarterly.
# JDK 26 was dropped from the table with this update: it is non-LTS, its
# support ended in September 2026, and the October CPU shipped no 26 build.
# Any 26 install is therefore unpatched and is now reported as outdated.
TABLE_SOURCE="OpenJDK out-of-band advisory for CVE-2026-91403 (2026-10-21)"
TABLE_DATE="2026-10-21"   # newest date in TABLE_SOURCE; shown in the banner
NEXT_UPDATE="2026-11-17 (November CSPU)"
VERSION_TABLE="8:511 11:33.0.2 17:21.0.2 21:13.0.2 25:5.0.2 27:1.0.2"

# ---- ZULU BUILD TABLE - UPDATE WITH EVERY AZUL RELEASE ----
# Azul ships some fixes without changing the OpenJDK version: the eMudhra fix
# of 2026-10-21 went out as Zulu 21.54.107 still reporting JAVA_VERSION
# 21.0.13, identical to the vulnerable 21.54.105. A Zulu install therefore has
# to be judged on its Zulu build number, not on JAVA_VERSION.
#
# <feature>:<minor>=<floor>,<minor>=<floor>
# Azul runs two supported tracks per release, PSU and CPU, and the CPU track
# sits on a lower minor. Both are listed so neither is wrongly flagged.
# The floor is the CA number; the SA build is one higher and also passes.
ZULU_TABLE="8:98=0.107,97=0.110 11:92=109,91=112 17:70=111,69=112 21:54=107,53=112 25:38=107,37=114 27:30=107"
# ------------------------------------------------------------

XRAY_VERSION="1.2.0"   # keep in step with the Version line at the top
AZUL_CONTACT="https://www.azul.com/products/core/#contact"
AZUL_DOWNLOADS="https://www.azul.com/downloads/"
AZUL_GET_PATCHED="https://azul.com/get-patched"
AZUL_RISK_ASSESSMENT="https://www.azul.com/jvm-vulnerability-risk-assessment/"

# Color only when writing to a terminal. NO_COLOR (https://no-color.org)
# turns it off, so piped and logged output stays plain text.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    ESC=$(printf '\033')
    C_BOLD="$ESC[1m"; C_DIM="$ESC[2m"; C_URL="$ESC[4;36m"; C_OFF="$ESC[0m"
    B_RED="$ESC[1;97;41m"; B_YEL="$ESC[1;30;43m"; B_GRN="$ESC[1;97;42m"
else
    C_BOLD=; C_DIM=; C_URL=; C_OFF=; B_RED=; B_YEL=; B_GRN=
fi

# badge <color> <LABEL> <headline>: a colored label, or [LABEL] when plain.
badge() {
    if [ -n "$1" ]; then printf '%s %s %s  %s%s%s\n' "$1" "$2" "$C_OFF" "$C_BOLD" "$3" "$C_OFF"
    else printf '[%s]  %s\n' "$2" "$3"; fi
}
# link <label> <url>: one aligned line per next step.
link() { printf '  %-38s %s%s%s\n' "$1" "$C_URL" "$2" "$C_OFF"; }

WORK=$(mktemp -d 2>/dev/null) || WORK=/tmp/jcc.$$
mkdir -p "$WORK" 2>/dev/null
PROBLEM_FILE="$WORK/problems"
SEEN_FILE="$WORK/seen"
: > "$PROBLEM_FILE"
: > "$SEEN_FILE"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM


# --- version table -----------------------------------------------------------

# Split a version string into FEATURE and REST, where REST is everything
# after the interim component, kept whole and dotted.
# Handles: 1.8.0_511 | 21.0.13 | 21.0.13.0.2 | 21.0.13+9 | 21.0.12.1.101 | 27
#
# REST is never truncated. An out-of-band fix can land as a fourth or fifth
# component -- 21.0.13.0.2 carries the eMudhra fix and 21.0.13 does not -- so
# every component has to survive to the comparison.
parse_version() {
    v=${1%%+*}
    v=${v%%-*}
    case "$v" in
        1.[0-9].0_*)  FEATURE=${v%%.0_*}; FEATURE=${FEATURE#1.}; REST=${v#*_} ;;
        1.[0-9]*)     FEATURE=${v#1.};    FEATURE=${FEATURE%%.*}; REST=0 ;;
        *.*)          FEATURE=${v%%.*}
                      rest=${v#*.}                    # drop the feature
                      case "$rest" in
                          *.*) REST=${rest#*.} ;;     # drop the interim
                          *)   REST=0 ;;
                      esac ;;
        *)            FEATURE=$v; REST=0 ;;
    esac
    case "$FEATURE" in ''|*[!0-9]*) return 1 ;; esac
    case "$REST"    in ''|*[!0-9.]*) return 1 ;; esac
    return 0
}

# True if dotted version $1 is at or above dotted version $2. Components are
# compared numerically left to right and a missing component counts as zero,
# so 13 ranks below 13.0.2 while 14 ranks above it.
ver_ge() {
    a=$1; b=$2
    while [ -n "$a" ] || [ -n "$b" ]; do
        case "$a" in *.*) ai=${a%%.*}; a=${a#*.} ;; *) ai=$a; a= ;; esac
        case "$b" in *.*) bi=${b%%.*}; b=${b#*.} ;; *) bi=$b; b= ;; esac
        [ -n "$ai" ] || ai=0
        [ -n "$bi" ] || bi=0
        [ "$ai" -gt "$bi" ] && return 0
        [ "$ai" -lt "$bi" ] && return 1
    done
    return 0
}

# Echo "<major> <minor> <rest>" from a Zulu build string, or return non-zero.
# Two formats are in the wild, confirmed against real installs:
#   Java 9+ : Zulu21.54+107-CA          -> 21 54 107
#   Java 8  : Zulu 8.98.0.107-CA-win64  -> 8 98 0.107
zulu_build_in() {
    case "$1" in *Zulu*) ;; *) return 1 ;; esac
    z=$(printf '%s' "$1" | sed -n 's/.*Zulu\([0-9][0-9]*\)\.\([0-9][0-9]*\)+\([0-9][0-9.]*\).*/\1 \2 \3/p' | head -1)
    [ -n "$z" ] || z=$(printf '%s' "$1" | sed -n 's/.*Zulu \([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9.]*\).*/\1 \2 \3/p' | head -1)
    [ -n "$z" ] || return 1
    printf '%s' "$z"
}

# Echo the floor for one Zulu track, or return non-zero if that track is not
# in the table.
zulu_floor_for() {
    for entry in $ZULU_TABLE; do
        [ "${entry%%:*}" = "$1" ] || continue
        OIFS=$IFS; IFS=,
        for t in ${entry#*:}; do
            IFS=$OIFS
            if [ "${t%%=*}" = "$2" ]; then printf '%s' "${t#*=}"; return 0; fi
            IFS=,
        done
        IFS=$OIFS
    done
    return 1
}

# Echo the highest Zulu minor known for a feature release, or 0 if none.
# Used to tell "older than every track we know" from "newer than our data".
zulu_max_minor() {
    m=0
    for entry in $ZULU_TABLE; do
        [ "${entry%%:*}" = "$1" ] || continue
        OIFS=$IFS; IFS=,
        for t in ${entry#*:}; do
            IFS=$OIFS
            k=${t%%=*}
            [ "$k" -gt "$m" ] && m=$k
            IFS=,
        done
        IFS=$OIFS
    done
    printf '%s' "$m"
}

min_patch_for() {
    for entry in $VERSION_TABLE; do
        if [ "${entry%%:*}" = "$1" ]; then
            printf '%s' "${entry#*:}"
            return 0
        fi
    done
    return 1
}


NEWEST_KNOWN=0
for entry in $VERSION_TABLE; do
    f=${entry%%:*}
    [ "$f" -gt "$NEWEST_KNOWN" ] && NEWEST_KNOWN=$f
done


# --- identifying Java --------------------------------------------------------

# True if the directory holds Java files
is_java_dir() {
    d=$1
    [ -e "$d/bin/java" ] && return 0
    [ -f "$d/lib/rt.jar" ] && return 0
    [ -f "$d/lib/modules" ] && return 0
    [ -f "$d/release" ] && grep -q '^JAVA_VERSION' "$d/release" 2>/dev/null && return 0
    for f in "$d"/lib/libjvm.* "$d"/lib/*/libjvm.* "$d"/lib/*/*/libjvm.*; do
        [ -f "$f" ] && return 0
    done
    return 1
}

# Strip a marker file path back to the Java home that contains it.
home_from_marker() {
    case "$1" in
        */bin/java)      printf '%s' "${1%/bin/java}" ;;
        */release)       printf '%s' "${1%/release}" ;;
        */lib/rt.jar)    printf '%s' "${1%/lib/rt.jar}" ;;
        */lib/modules)   printf '%s' "${1%/lib/modules}" ;;
        */lib/*libjvm.*) printf '%s' "${1%/lib/*}" ;;
        *)               printf '%s' "$1" ;;
    esac
}

# Read the version out of libjvm's embedded VM string.
read_version_from_libjvm() {
    for f in "$1"/lib/server/libjvm.* "$1"/lib/client/libjvm.* \
             "$1"/lib/*/server/libjvm.* "$1"/jre/lib/*/server/libjvm.*; do
        [ -f "$f" ] || continue
        s=$(strings "$f" 2>/dev/null | grep -m1 -E '(OpenJDK|GraalVM|Java HotSpot).*VM \(' 2>/dev/null)
        [ -n "$s" ] || s=$(LC_ALL=C tr '\0' '\n' < "$f" 2>/dev/null | grep -m1 -E '(OpenJDK|GraalVM|Java HotSpot).*VM \(' 2>/dev/null)
        [ -n "$s" ] || continue
        v=${s##*\(}
        v=${v%%\)*}
        case "$v" in
            # Legacy HotSpot numbering: 25.302-b08 is Java 8u302, 24.x is 7.
            25.*-b*) printf '1.8.0_%s|%s' "$(x=${v#25.}; printf '%s' "${x%%-*}")" "$s"; return 0 ;;
            24.*-b*) printf '1.7.0_%s|%s' "$(x=${v#24.}; printf '%s' "${x%%-*}")" "$s"; return 0 ;;
            *)       printf '%s|%s' "${v%%+*}" "$s"; return 0 ;;
        esac
    done
    return 1
}

# Echo "version|vendor". Order of preference: the release file (plain text,
# safe, gives the vendor), then libjvm's VM string, then executing the
# launcher, then the directory name.
read_version() {
    h=$1
    zb=
    if [ -f "$h/release" ]; then
        v=$(sed -n 's/^JAVA_VERSION="\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$h/release" 2>/dev/null | head -1)
        i=$(sed -n 's/^IMPLEMENTOR="\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$h/release" 2>/dev/null | head -1)
        # Azul puts the Zulu build in IMPLEMENTOR_VERSION. It is the only
        # thing that moves when a fix ships without an OpenJDK version change.
        iv=$(sed -n 's/^IMPLEMENTOR_VERSION="\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$h/release" 2>/dev/null | head -1)
        zb=$(zulu_build_in "$iv") || zb=
        if [ -n "$v" ]; then
            printf '%s|%s|%s' "$v" "${i:-unknown}" "$zb"
            return 0
        fi
    fi
    s=$(read_version_from_libjvm "$h" 2>/dev/null)
    v=${s%%|*}
    if [ -n "$v" ]; then
        [ -n "$zb" ] || zb=$(zulu_build_in "${s#*|}") || zb=
        printf '%s|%s|%s' "$v" "unknown (read from libjvm)" "$zb"
        return 0
    fi
    if [ -x "$h/bin/java" ]; then
        # Match the 'version "X"' line rather than the first line: a set
        # JAVA_TOOL_OPTIONS or _JAVA_OPTIONS prints a "Picked up ..." banner
        # ahead of it, which would otherwise swallow the result.
        out=$("$h/bin/java" -version 2>&1)
        v=$(printf '%s\n' "$out" | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
        [ -n "$zb" ] || zb=$(zulu_build_in "$out") || zb=
        if [ -n "$v" ]; then
            printf '%s|%s|%s' "$v" "unknown (read from java -version)" "$zb"
            return 0
        fi
    fi
    v=$(basename "$h" | sed -n 's/.*\(1\.[4-8]\.0_[0-9]\{1,\}\).*/\1/p')
    if [ -n "$v" ]; then
        printf '%s|%s|%s' "$v" "unknown (version inferred from path)" ""
        return 0
    fi
    return 1
}

# Last resort for a remnant: the major version out of the directory name.
infer_feature() {
    basename "$1" | sed -n 's/^[A-Za-z_-]*-\{0,1\}\([0-9]\{1,2\}\)[.-].*/\1/p;s/^[A-Za-z_-]*-\{0,1\}\([0-9]\{1,2\}\)$/\1/p' | head -1
}


# --- classification ----------------------------------------------------------

# Returns 1 as soon as an outdated Java is identified, which unwinds the scan.
# Everything else is recorded and the scan continues.
classify() {
    h=$1
    [ -n "$h" ] || return 0
    # The macOS /usr/bin/java stub resolves to /usr and is not an install.
    case "$h" in /|/usr|/usr/bin) return 0 ;; esac
    # The Oracle shim directory on Windows-style layouts, and Java's own
    # per-user caches, are pointers rather than installs.
    case "$h" in *"Common Files"*) return 0 ;; esac
    is_java_dir "$h" || return 0

    grep -qxF "$h" "$SEEN_FILE" 2>/dev/null && return 0
    printf '%s\n' "$h" >> "$SEEN_FILE"

    info=$(read_version "$h")
    if [ -z "$info" ]; then
        feat=$(infer_feature "$h")
        if [ -n "$feat" ]; then
            printf '%s\n' "$h (Java $feat files present, no readable version)" >> "$PROBLEM_FILE"
        else
            printf '%s\n' "$h (Java files present, version could not be determined)" >> "$PROBLEM_FILE"
        fi
        return 0
    fi

    ver=${info%%|*}
    rest_fields=${info#*|}
    vendor=${rest_fields%%|*}
    zbuild=${rest_fields#*|}
    [ "$zbuild" = "$vendor" ] && zbuild=

    # A Zulu install is judged on its Zulu build number. Azul ships fixes that
    # do not move the OpenJDK version, so JAVA_VERSION cannot separate a
    # patched build from the vulnerable one it replaced.
    if [ -n "$zbuild" ]; then
        zmaj=${zbuild%% *}; zr=${zbuild#* }; zmin=${zr%% *}; zrest=${zr#* }
        if zfloor=$(zulu_floor_for "$zmaj" "$zmin"); then
            ver_ge "$zrest" "$zfloor" && return 0
            return 1
        fi
        zmax=$(zulu_max_minor "$zmaj")
        if [ "$zmax" != "0" ]; then
            if [ "$zmin" -gt "$zmax" ]; then
                printf '%s\n' "$h (Zulu $zmaj.$zmin.$zrest is newer than this script's data)" >> "$PROBLEM_FILE"
                return 0
            fi
            return 1
        fi
        # Feature release absent from the Zulu table: fall through to the
        # OpenJDK comparison below.
    fi

    if ! parse_version "$ver"; then
        printf '%s\n' "$h (unparseable version string \"$ver\")" >> "$PROBLEM_FILE"
        return 0
    fi

    if floor=$(min_patch_for "$FEATURE"); then
        if ver_ge "$REST" "$floor"; then
            return 0
        fi
        return 1
    elif [ "$FEATURE" -gt "$NEWEST_KNOWN" ]; then
        printf '%s\n' "$h (Java $ver is newer than this script's data from $TABLE_SOURCE)" >> "$PROBLEM_FILE"
        return 0
    else
        return 1
    fi
}

# Feed a stream of marker paths through classification. Returns 1 if the
# stream was cut short because an outdated Java was found; closing the pipe
# also kills the producing find, so the walk stops there.
consume() {
    while IFS= read -r m; do
        classify "$(home_from_marker "$m")" || exit 1
    done
    exit 0
}


# --- phase 1: standard install locations -------------------------------------

scan_known() {
    [ -d "$1" ] || return 0
    find "$1" -maxdepth 6 \
        \( -name node_modules -o -name .git -o -name .svn -o -name .cache \) -prune -o \
        \( -type f -o -type l \) \
        \( -path '*/bin/java' -o -path '*/release' -o -path '*/lib/rt.jar' \
           -o -path '*/lib/modules' -o -name 'libjvm.so' -o -name 'libjvm.dylib' \) \
        -print 2>/dev/null | consume
}

phase_one() {
    for r in \
        /usr/lib/jvm /usr/lib64/jvm /usr/java /opt /usr/local /snap /srv \
        /Library/Java "/Library/Internet Plug-Ins" /Applications \
        "$HOME/Library/Java" "$HOME/.sdkman/candidates/java" "$HOME/.jdks" \
        "$HOME/.jenv/versions" "$HOME/.gradle/jdks" "$HOME/.asdf" \
        "$HOME/Downloads" "$HOME/Desktop" "$HOME/Applications" "$HOME/tools"
    do
        scan_known "$r" || return 1
    done

    # macOS keeps its own registry of installed JVMs. Note it writes to stderr.
    if [ -x /usr/libexec/java_home ]; then
        for d in $(/usr/libexec/java_home -V 2>&1 | grep -oE '/[^"]*/Contents/Home'); do
            classify "$d" || return 1
        done
    fi

    if [ -n "${JAVA_HOME:-}" ]; then
        if [ -d "$JAVA_HOME" ]; then
            classify "$JAVA_HOME" || return 1
        else
            printf '%s\n' "JAVA_HOME is set to \"$JAVA_HOME\" but that directory does not exist" >> "$PROBLEM_FILE"
        fi
    fi

    jbin=$(command -v java 2>/dev/null)
    if [ -n "$jbin" ]; then
        real=$jbin
        n=0
        while [ -L "$real" ] && [ $n -lt 10 ]; do
            link=$(ls -ld "$real" | sed 's/.* -> //')
            case "$link" in
                /*) real=$link ;;
                *)  real=$(dirname "$real")/$link ;;
            esac
            n=$((n + 1))
        done
        classify "$(dirname "$(dirname "$real")")" || return 1
    fi
    return 0
}


# --- phase 2: full disk ------------------------------------------------------
# Only reached when phase 1 found nothing outdated.

phase_two() {
    find / \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run \
           -o -path /var/folders -o -path /private/var/folders \
           -o -path /System/Volumes -o -path /Volumes -o -path /net \
           -o -path /mnt -o -path /media \
           -o -name node_modules -o -name .git -o -name .svn \
           -o -name '.Trash' -o -name '.Trashes' -o -name '.MobileBackups' \
           -o -name '.Spotlight-V100' -o -name '.DocumentRevisions-V100' \) -prune -o \
        \( -type f -o -type l \) \
        \( -path '*/bin/java' -o -path '*/release' -o -path '*/lib/rt.jar' \
           -o -path '*/lib/modules' -o -name 'libjvm.so' -o -name 'libjvm.dylib' \) \
        -print 2>/dev/null | consume
}


# --- run ---------------------------------------------------------------------

echo "Checking for outdated Java, please wait..." >&2

FOUND_VULN=0
phase_one || FOUND_VULN=1

if [ "$FOUND_VULN" -eq 0 ]; then
    echo "Nothing outdated in the usual places. Widening the search..." >&2
    phase_two || FOUND_VULN=1
fi

N_PROBLEM=$(sort -u "$PROBLEM_FILE" 2>/dev/null | grep -c . 2>/dev/null)
[ -n "$N_PROBLEM" ] || N_PROBLEM=0
N_SEEN=$(grep -c . "$SEEN_FILE" 2>/dev/null)
[ -n "$N_SEEN" ] || N_SEEN=0


# --- report ------------------------------------------------------------------

RULE="==============================================================="
echo ""
echo "$C_DIM$RULE$C_OFF"
echo " ${C_BOLD}Azul JDK XRay$C_OFF"
echo " Checks this machine for outdated, unpatched JDK installations."
echo " Local scan only: no network calls, nothing leaves this host."
echo ""
echo " ${C_DIM}Version $XRAY_VERSION | Reference data: $TABLE_DATE$C_OFF"
echo "$C_DIM$RULE$C_OFF"
echo ""

if [ "$FOUND_VULN" -eq 1 ]; then
    badge "$B_RED" "OUTDATED" "This host runs an outdated JDK. Update it now."
    echo ""
    echo "The security flaws fixed since this release are publicly known."
    echo "CVE details and the source code for each fix have been published; so"
    echo "attackers know exactly what to target. Every day without updating"
    echo "adds to the risk."
    echo ""
    echo "  ${C_BOLD}Azul has the solution, process and tools to secure your$C_OFF"
    echo "  ${C_BOLD}Java estate at scale:$C_OFF"
    echo "    Get Patched Today"
    echo "    $C_URL$AZUL_GET_PATCHED$C_OFF"
    echo ""
    echo "  ${C_BOLD}To patch this machine right now download a free,$C_OFF"
    echo "  ${C_BOLD}unsupported Azul Zulu build of OpenJDK:$C_OFF"
    echo "    $C_URL$AZUL_DOWNLOADS$C_OFF"
    echo ""
    exit 1
fi

if [ "$N_SEEN" -eq 0 ] && [ "$N_PROBLEM" -eq 0 ]; then
    badge "$B_GRN" "NO JAVA" "No Java was detected."
    echo ""
    exit 3
fi

if [ "$N_PROBLEM" -gt 0 ]; then
    badge "$B_YEL" "UNKNOWN" "Java was found, but its version could not be identified."
    echo ""
    echo "Treat this as a problem, not a pass. An unidentified runtime may be"
    echo "unpatched, and files left behind by a removed install still carry the"
    echo "vulnerabilities of the version they came from."
    echo ""
    echo "  ${C_BOLD}Request a risk assessment of your enterprise Java estate.$C_OFF"
    echo "    $C_URL$AZUL_RISK_ASSESSMENT$C_OFF"
    echo ""
    exit 2
fi

badge "$B_GRN" "UP TO DATE" "Your Java is up to date."
echo ""
echo "  ${C_BOLD}For long-term enterprise Java support, contact Azul:$C_OFF"
echo "    $C_URL$AZUL_CONTACT$C_OFF"
echo ""
exit 0
