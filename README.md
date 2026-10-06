# Azul JDK X-Ray Tool

Version: 1.0.0 - October 5, 2026

A single-file script that answers one question: **is there a vulnerable Java on this machine?**

The Azul JDK X-Ray Tool is not an inventory tool. It does not tell you where the Java is or how much of it there is.

The Azul JDK X-Ray Tool looks for Java *files*.

The tool requires no arguments, no configuration, and no network calls. Simply download and run.

```
windows/azul-jdk-xray.ps1            Windows
macos-linux/azul-jdk-xray.sh         macOS and Linux
```

The two scripts are independent and behave identically. There is no shared code.

---

## Design

The Azul JDK X-Ray Tool runs in two phases and stops as soon as it finds any remnant of Java.

1. **Standard install locations**, depth-limited. Fast. Takes a second or two.
2. **Full disk**, only if phase 1 found nothing outdated. Catches a JDK that is just sitting somewhere on the disk. Maybe just unpacked or released by a third party application.

Note that phase 2 runs whenever phase 1 found nothing **outdated**, not whenever phase 1 found nothing at all.

---

## Run on Windows

**File:** `windows/azul-jdk-xray.ps1`
**Requires:** Windows PowerShell 5.1, built into Windows 10 and 11.

### Run

```powershell
powershell -ExecutionPolicy Bypass -File azul-jdk-xray.ps1
```

---

## Run on macOS and Linux

**File:** `macos-linux/azul-jdk-xray.sh`
**Requires:** any POSIX shell.

### Run

```sh
sh azul-jdk-xray.sh
```

## Detectable Java versions

Azul, Temurin, Microsoft, Corretto, SapMachine, Liberica and Oracle all build from the same OpenJDK upstream and ship the same version numbers. So the comparison needs only a feature release and a minimum patch level.

_Current table_ (August 2026 CSPU, released 2026-08-18; JDK 27 GA 2026-09-15):

| Feature release | Minimum acceptable |
|-----------------|--------------------|
| 8               | 8u503              |
| 11              | 11.0.32.1          |
| 17              | 17.0.20.1          |
| 21              | 21.0.12.1          |
| 25              | 25.0.4.1           |
| 26              | 26.0.2.1           |
| 27              | 27 (GA, no update yet) |

For JDK 8 the floor is Oracle's update number (8u503). OpenJDK-derived builds are one ahead (8u504); using the lower of the two avoids false alarms.

A feature release **not** in the table is handled by comparing it to the newest
release the table knows about:

- Java 6, 7, 9, 10, 12–16, 18–20, 22–24 are all flagged as **outdated**.
- If a newer Java version (28) is found, it is flagged as **unidentifiable**.

NOTE: The Azul JDK X-Ray Tool does not check for Zing versions explicitly, which may raise false flags if Zing is present.

### Maintaining the table

At each release, the `TableSource` / `TABLE_SOURCE` must be updated.

### What counts as a finding

A directory is examined if it contains **any** of these, whether or not the install is complete or runnable:

| Marker | Meaning |
|--------|---------|
| `bin/java` / `bin\java.exe` | A runnable runtime |
| `release` containing `JAVA_VERSION` | Version metadata (JDK 9+) |
| `lib/rt.jar` | Class library, JDK 8 and earlier |
| `lib/modules` | Class library, JDK 9+ (the jimage **file**) |
| `libjvm.so` / `libjvm.dylib` / `jvm.dll` | The VM itself |

Requiring a working `bin/java` is the wrong approach. A half-removed JDK 8 with no launcher but with `rt.jar` and `jvm.dll` are still on disk is still loadable by anything that embeds a JVM. The `libjvm` marker also catches an application that embeds a JVM through JNI and ships no launcher at all.

- **Markers must be files.**
- **Only a confirmed Java home ends the run.**

### How versions are determined

In order of preference:

1. **The `release` file**
2. **The VM string inside `libjvm.so` / `jvm.dll`**
3. **The PE version resource** on Windows (`java.exe`)
4. **`java -version`**. Last resort before guessing.
5. **The directory name**
6. If no version is found, simply classify the remnants as "unidentifiable."

### Exit codes

| Code | Meaning                                                     |
|------|-------------------------------------------------------------|
| 0    | Java found, everything up-to-date                           |
| 1    | Outdated Java found                                         |
| 2    | Nothing confirmed outdated, but unidentifiable Java present |
| 3    | No Java detected                                            |

---

## Versioning

`MM.VV.TV`

- **MM**: The tool's major version. Only changes in case of a major overhaul. 0 indicates a pre-production build. 1 or higher indicates a release build.
- **VV**: Version of this tool. Changes when there are updates to the code itself - improvements, bug fixes in the code base, etc.
- **TV**: Table version. Bumps up every time the version table is updated.
