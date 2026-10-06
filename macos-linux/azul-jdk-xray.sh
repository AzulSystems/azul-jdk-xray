#!/bin/sh
# Azul JDK X-Ray Tool for macOS / Linux.
# Version 1.0.0
# Run:  sh azul-jdk-xray.sh
# Exit: 0 - no exposure found | 1 - outdated Java found | 2 - undetermined | 3 no Java found

# ---- VERSION TABLE ----
# <feature release>:<minimum acceptable patch level>
# A patch level may carry a CSPU revision: 12.1 means 21.0.12.1, which ranks
# above 21.0.12. OpenJDK ships CSPUs between quarterly CPUs, so this table
# goes stale monthly, not quarterly.
TABLE_SOURCE="August 2026 CSPU (2026-08-18); JDK 27 GA (2026-09-15)"
TABLE_DATE="2026-09-15"   # newest date in TABLE_SOURCE; shown in the banner
NEXT_UPDATE="2026-10-20 (October CPU)"
VERSION_TABLE="8:503 11:32.1 17:20.1 21:12.1 25:4.1 26:2.1 27:0"
# ------------------------------------------------------------

XRAY_VERSION="1.0.0"   # keep in step with the Version line at the top
AZUL_CONTACT="https://www.azul.com/contact/"
AZUL_DOWNLOADS="https://www.azul.com/downloads/"

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

# Split a version string into FEATURE, PATCH and SUB (the CSPU revision).
# Handles: 1.8.0_503 | 21.0.12 | 21.0.12.1 | 21.0.12.1+1 | 21.0.12.9.1 | 27
parse_version() {
    v=${1%%+*}
    v=${v%%-*}
    SUB=0
    case "$v" in
        1.[0-9].0_*)  FEATURE=${v%%.0_*}; FEATURE=${FEATURE#1.}; PATCH=${v#*_} ;;
        1.[0-9]*)     FEATURE=${v#1.};    FEATURE=${FEATURE%%.*}; PATCH=0 ;;
        # Five or more components are vendor build numbers appended to the
        # OpenJDK patch (Corretto 21.0.12.9.1), not a CSPU revision.
        *.*.*.*.*)    FEATURE=${v%%.*}
                      rest=${v#*.}
                      PATCH=${rest#*.}
                      PATCH=${PATCH%%.*} ;;
        *.*.*.*)      FEATURE=${v%%.*}
                      rest=${v#*.}; rest=${rest#*.}
                      PATCH=${rest%%.*}
                      SUB=${rest#*.}; SUB=${SUB%%.*} ;;
        *.*.*)        FEATURE=${v%%.*}
                      rest=${v#*.}
                      PATCH=${rest#*.}
                      PATCH=${PATCH%%.*} ;;
        *.*)          FEATURE=${v%%.*}; PATCH=0 ;;
        *)            FEATURE=$v;       PATCH=0 ;;
    esac
    case "$FEATURE" in ''|*[!0-9]*) return 1 ;; esac
    case "$PATCH"   in ''|*[!0-9]*) return 1 ;; esac
    case "$SUB"     in ''|*[!0-9]*) SUB=0 ;; esac
    return 0
}

# "12.1" -> 12001, "12" -> 12000, so a CSPU revision ranks above the CPU it
# patches. Leading zeros are stripped to avoid invalid octal literals.
vnum() {
    p=${1%%.*}; s=${1#*.}
    [ "$s" = "$1" ] && s=0
    p=${p#0}; s=${s#0}
    printf '%s' $(( ${p:-0} * 1000 + ${s:-0} ))
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
            25.*-b*) printf '1.8.0_%s' "$(x=${v#25.}; printf '%s' "${x%%-*}")"; return 0 ;;
            24.*-b*) printf '1.7.0_%s' "$(x=${v#24.}; printf '%s' "${x%%-*}")"; return 0 ;;
            *)       printf '%s' "${v%%+*}"; return 0 ;;
        esac
    done
    return 1
}

# Echo "version|vendor". Order of preference: the release file (plain text,
# safe, gives the vendor), then libjvm's VM string, then executing the
# launcher, then the directory name.
read_version() {
    h=$1
    if [ -f "$h/release" ]; then
        v=$(sed -n 's/^JAVA_VERSION="\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$h/release" 2>/dev/null | head -1)
        i=$(sed -n 's/^IMPLEMENTOR="\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$h/release" 2>/dev/null | head -1)
        if [ -n "$v" ]; then
            printf '%s|%s' "$v" "${i:-unknown}"
            return 0
        fi
    fi
    v=$(read_version_from_libjvm "$h")
    if [ -n "$v" ]; then
        printf '%s|%s' "$v" "unknown (read from libjvm)"
        return 0
    fi
    if [ -x "$h/bin/java" ]; then
        # Match the 'version "X"' line rather than the first line: a set
        # JAVA_TOOL_OPTIONS or _JAVA_OPTIONS prints a "Picked up ..." banner
        # ahead of it, which would otherwise swallow the result.
        v=$("$h/bin/java" -version 2>&1 | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
        if [ -n "$v" ]; then
            printf '%s|%s' "$v" "unknown (read from java -version)"
            return 0
        fi
    fi
    v=$(basename "$h" | sed -n 's/.*\(1\.[4-8]\.0_[0-9]\{1,\}\).*/\1/p')
    if [ -n "$v" ]; then
        printf '%s|%s' "$v" "unknown (version inferred from path)"
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
    vendor=${info#*|}

    if ! parse_version "$ver"; then
        printf '%s\n' "$h (unparseable version string \"$ver\")" >> "$PROBLEM_FILE"
        return 0
    fi

    if floor=$(min_patch_for "$FEATURE"); then
        if [ "$(vnum "$PATCH.$SUB")" -ge "$(vnum "$floor")" ]; then
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
    echo "The security flaws fixed since this release are publicly disclosed."
    echo "Their CVE details and the source code of the fixes are published, so"
    echo "attackers know exactly what to target. Every day without the update"
    echo "adds to the risk."
    echo ""
    echo "  ${C_BOLD}Secure Java across your enterprise:$C_OFF"
    echo "    Azul has the solution, process and tools to do it at scale."
    echo "    $C_URL$AZUL_CONTACT$C_OFF"
    echo ""
    echo "  ${C_BOLD}Patch this machine right now:$C_OFF"
    echo "    Download free Azul Zulu builds of OpenJDK (no commercial support)."
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
    link "Review your enterprise Java estate:" "$AZUL_CONTACT"
    echo ""
    exit 2
fi

badge "$B_GRN" "UP TO DATE" "Your Java is up to date."
echo ""
link "Long-term enterprise Java support:" "$AZUL_CONTACT"
echo ""
exit 0
