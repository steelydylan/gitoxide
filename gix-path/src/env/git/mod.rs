use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use bstr::{BStr, BString};
use std::sync::LazyLock;

/// Other places to find Git in.
#[cfg(windows)]
pub(super) static ALTERNATIVE_LOCATIONS: LazyLock<Vec<PathBuf>> =
    LazyLock::new(|| locations_under_program_files(|key| std::env::var_os(key)));
#[cfg(not(windows))]
pub(super) static ALTERNATIVE_LOCATIONS: LazyLock<Vec<PathBuf>> = LazyLock::new(Vec::new);

#[cfg(windows)]
pub(super) fn locations_under_program_files<F>(mut var_os_func: F) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<std::ffi::OsString>,
{
    // Should give a 64-bit program files path from a 32-bit or 64-bit process on a 64-bit system.
    let varname_64bit = "ProgramW6432";

    // Should give a 32-bit program files path from a 32-bit or 64-bit process on a 64-bit system.
    // This variable is x86-specific, but neither Git nor Rust target 32-bit ARM on Windows.
    let varname_x86 = "ProgramFiles(x86)";

    // Should give a 32-bit program files path on a 32-bit system. We also check this on a 64-bit
    // system, even though it *should* equal the process's architecture-specific variable, so that
    // we cover the case of a parent process that passes down an overly sanitized environment that
    // lacks the architecture-specific variable. On a 64-bit system, because parent and child
    // processes' architectures can be different, Windows sets the child's `ProgramFiles` variable
    // from whichever of the `ProgramW6432` or `ProgramFiles(x86)` variable corresponds to the
    // child's architecture. Only if the parent does not pass down the architecture-specific
    // variable corresponding to the child's architecture does the child receive its `ProgramFiles`
    // variable from `ProgramFiles` as passed down by the parent. But this behavior is not well
    // known. So the situation where a process only passes down `ProgramFiles` sometimes happens.
    let varname_current = "ProgramFiles";

    // Should give the user's local application data path on any system. If a user program files
    // directory exists for this user, then it should be the `Programs` subdirectory of this. If it
    // doesn't exist, or on a future or extremely strangely configured Windows setup where it is
    // somewhere else, it should still be safe to attempt to use it. (This differs from global
    // program files paths, which are usually subdirectories of the root of the system drive, which
    // limited user accounts can usually create their own arbitrarily named directories inside.)
    let varname_user_appdata_local = "LocalAppData";

    // Prefer native ARM64 over an emulated x86_64 executable when both are present.
    // For x86_64, Git for Windows 2.56 uses `ucrt64`; keep `mingw64` for older releases.
    let suffixes_64 = &[r"Git\clangarm64\bin", r"Git\ucrt64\bin", r"Git\mingw64\bin"][..];

    // 32-bit relative bin dirs. So far, this is only ever `mingw32`, not `clang32`.
    let suffixes_32 = &[r"Git\mingw32\bin"][..];

    // Whichever of the 64-bit or 32-bit relative bin better matches this process's architecture.
    // Unlike the system architecture, the process architecture is always known at compile time.
    #[cfg(target_pointer_width = "64")]
    let suffixes_current = suffixes_64;
    #[cfg(target_pointer_width = "32")]
    let suffixes_current = suffixes_32;

    // Bin dirs relative to a user's local application data directory. We try each architecture.
    let suffixes_user = &[
        r"Programs\Git\clangarm64\bin",
        r"Programs\Git\ucrt64\bin",
        r"Programs\Git\mingw64\bin",
        r"Programs\Git\mingw32\bin",
    ][..];

    let rules = [
        (varname_user_appdata_local, suffixes_user),
        (varname_64bit, suffixes_64),
        (varname_x86, suffixes_32),
        (varname_current, suffixes_current),
    ];

    let mut locations = vec![];

    for (varname, suffixes) in rules {
        let Some(program_files_dir) = var_os_func(varname).map(PathBuf::from).filter(|p| p.is_absolute()) else {
            // The environment variable is unset or somehow not an absolute path (e.g. an empty string).
            continue;
        };
        for suffix in suffixes {
            let location = program_files_dir.join(suffix);
            if !locations.contains(&location) {
                locations.push(location);
            }
        }
    }

    locations
}

#[cfg(windows)]
pub(super) const EXE_NAME: &str = "git.exe";
#[cfg(not(windows))]
pub(super) const EXE_NAME: &str = "git";

#[derive(Debug, Default, Eq, PartialEq)]
struct ConfigPaths {
    installation: Option<BString>,
    installation_is_system: bool,
    system: Option<BString>,
}

/// Cache conventional configuration locations without executing Git. Environment overrides of
/// configuration files and helper paths are intentionally applied by callers, not discovery.
static GIT_CONFIG_PATHS: LazyLock<ConfigPaths> = LazyLock::new(|| {
    std::env::current_dir()
        .ok()
        .map(|cwd| config_paths_from_environment(|key| std::env::var_os(key), &cwd))
        .unwrap_or_default()
});

fn config_paths_from_environment(
    mut environment: impl FnMut(&str) -> Option<OsString>,
    current_dir: &Path,
) -> ConfigPaths {
    if !current_dir.is_absolute() {
        return ConfigPaths::default();
    }
    let directories = super::installation::search_directories(&mut environment, current_dir);
    let mut prefixes = Vec::new();
    #[cfg(windows)]
    if let Some(prefix) = super::system_prefix_from_exepath_var(&mut environment) {
        prefixes.push(prefix);
    }
    if prefixes.is_empty() {
        if let Some(directory) = directories.iter().find(|directory| directory.join(EXE_NAME).is_file()) {
            // Preserve a package manager's stable symlink prefix before trying the versioned
            // installation itself, where helpers may live but configuration usually does not.
            if let Some(prefix) = directory.parent() {
                prefixes.push(prefix.to_path_buf());
            }
            if let Ok(executable) = std::fs::canonicalize(directory.join(EXE_NAME))
                && let Some(prefix) = executable.parent().and_then(Path::parent)
                && !prefixes.iter().any(|existing| existing == prefix)
            {
                prefixes.push(prefix.to_path_buf());
            }
            #[cfg(windows)]
            if let Some(core) = super::installation::core_from_bin(directory)
                && let Some(prefix) = core.parent().and_then(Path::parent)
            {
                prefixes.insert(0, prefix.to_path_buf());
            }
        } else if let Some(core) = directories
            .iter()
            .find_map(|dir| super::installation::core_from_bin(dir))
            && let Some(prefix) = core.parent().and_then(Path::parent)
        {
            prefixes.push(prefix.to_path_buf());
        }
    }
    #[cfg(target_os = "macos")]
    if prefixes.iter().any(|prefix| prefix == Path::new("/usr"))
        && let Some(prefix) = super::installation::developer_prefix(&mut environment)
    {
        prefixes.push(prefix);
    }
    let system = if cfg!(windows) {
        prefixes
            .first()
            .map(|prefix| super::config_path_from_system_prefix(prefix))
    } else {
        Some(
            prefixes
                .iter()
                .map(|prefix| {
                    if prefix == Path::new("/usr") {
                        PathBuf::from("/etc/gitconfig")
                    } else {
                        prefix.join("etc/gitconfig")
                    }
                })
                .find(|path| path.is_file())
                .unwrap_or_else(|| "/etc/gitconfig".into()),
        )
    };
    let installation = prefixes
        .iter()
        .map(|prefix| prefix.join("share/git-core/gitconfig"))
        .find(|path| path.is_file());
    let installation_is_system = installation.is_none();
    #[cfg(windows)]
    let installation = installation.or_else(|| {
        environment("PROGRAMDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join("Git/config"))
            .filter(|path| path.is_file())
    });
    let installation = installation.or_else(|| system.as_ref().filter(|path| cfg!(windows) || path.is_file()).cloned());
    ConfigPaths {
        installation_is_system: installation_is_system && installation.is_some(),
        installation: installation.and_then(|path| crate::os_string_into_bstring(path.into()).ok()),
        system: system.and_then(|path| crate::os_string_into_bstring(path.into()).ok()),
    }
}

/// Try to find configuration associated with a conventional Git installation.
pub(super) fn install_config_path() -> Option<&'static BStr> {
    let _span = gix_trace::detail!("gix_path::git::install_config_path()");
    GIT_CONFIG_PATHS.installation.as_ref().map(AsRef::as_ref)
}

pub(super) fn install_config_is_system() -> bool {
    GIT_CONFIG_PATHS.installation_is_system
}

pub(super) fn system_config_path() -> Option<&'static BStr> {
    let _span = gix_trace::detail!("gix_path::git::system_config_path()");
    GIT_CONFIG_PATHS.system.as_ref().map(AsRef::as_ref)
}

/// Given `config_path` as obtained from `install_config_path()`, return the path of the git installation base.
pub(super) fn config_to_base_path(config_path: &Path) -> &Path {
    config_path
        .parent()
        .expect("config file paths always have a file name to pop")
}

#[cfg(test)]
mod tests;
